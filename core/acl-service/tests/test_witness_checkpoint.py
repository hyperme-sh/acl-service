"""Internal checkpoint signing; management authority provenance remains external."""
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import replace
from pathlib import Path
from threading import Event
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from sqlalchemy import event
from sqlalchemy.orm import Session
from controlplane_db.models import SociaclWitnessPolicy
from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_policy_repo import install_verified_policy
from acl_service.infrastructure.witness_signer import P256_ORDER, WitnessRejected
from test_witness_policy_repo import engine  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401

FIXTURE=json.loads(Path(__file__).with_name('fixtures').joinpath('sociacl-policy-snapshot.json').read_text())
MANAGEMENT=ec.derive_private_key(18,ec.SECP256R1())
ROOT=ec.derive_private_key(17,ec.SECP256R1()).public_key()
CHALLENGE=base64.urlsafe_b64encode(bytes(range(32))).rstrip(b'=').decode()
def decode(v): return base64.urlsafe_b64decode(v+'='*(-len(v)%4))
def commitment(state): return hashlib.sha256(json.dumps(state,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).digest()

@pytest.fixture
def ready(engine,monkeypatch):
    state=FIXTURE['state']; envelope=json.loads(FIXTURE['policy'])
    monkeypatch.setattr(ingest.time,'time',lambda:FIXTURE['now'])
    with Session(engine) as session,session.begin():
        session.add(SociaclWitnessPolicy(id=1,revision=state['revision'],jwks=state['jwks'],history={e['jwk']['kid']:e for e in state['history']}))
    return dict(engine=engine,policy_payload=decode(envelope['payload']),policy_signature=decode(envelope['signature']),
        policy_root=ROOT,audience=state['audience'],management_private_key=MANAGEMENT,
        continuity=issuer.CheckpointContinuity(1,commitment(state)),client='client-enrollment-1',challenge=CHALLENGE)

def verify_response(response):
    outer=json.loads(response);assert set(outer)=={'type','checkpoint','policy'}
    assert outer['type']=='sociacl-witness-checkpoint-response-v1'
    envelope=json.loads(outer['checkpoint']);signature=decode(envelope['signature'])
    r,s=int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')
    assert len(signature)==64 and 0<s<=P256_ORDER//2
    payload=decode(envelope['payload'])
    MANAGEMENT.public_key().verify(utils.encode_dss_signature(r,s),issuer.DOMAIN+payload,ec.ECDSA(hashes.SHA256()))
    assert json.loads(outer['policy'])==json.loads(FIXTURE['policy'])
    return json.loads(payload)

def test_binds_complete_history_and_earlier_policy_expiry(ready):
    result=verify_response(issuer.sign_checkpoint_for_verified_refresh(**ready))
    assert result==dict(type='sociacl-witness-checkpoint-v1',audience=ready['audience'],client=ready['client'],challenge=CHALLENGE,
        rootEpoch=1,issuedAt=FIXTURE['now'],expiresAt=FIXTURE['now']+120,state=FIXTURE['state'])
    assert any(e['removed'] for e in result['state']['history'])
    assert verify_response(issuer.sign_checkpoint_for_verified_refresh(**ready,lifetime=5))['expiresAt']==FIXTURE['now']+5

@pytest.mark.parametrize('field,value',[('client',''),('client','x'*1025),('client','\ud800'),('audience','x'*1025),
    ('challenge',CHALLENGE+'='),('challenge','!'*43),('challenge','A'*42+'B'),('lifetime',0),('lifetime',301),
    ('lifetime',True),('lifetime',1.5),('expires_at_limit',True),('expires_at_limit',-1),('expires_at_limit',9007199254740992),('management_private_key',None),('management_private_key',ec.generate_private_key(ec.SECP384R1()))])
def test_invalid_inputs_before_database(ready,field,value):
    ready.update(engine=object());ready[field]=value
    with pytest.raises(WitnessRejected): issuer.sign_checkpoint_for_verified_refresh(**ready)

@pytest.mark.parametrize('continuity',[issuer.CheckpointContinuity(0,b'x'*32),issuer.CheckpointContinuity(True,b'x'*32),
    issuer.CheckpointContinuity(9007199254740992,b'x'*32),issuer.CheckpointContinuity(1,b'x'*31),issuer.CheckpointContinuity(1,'x'*32),None])
def test_invalid_continuity_before_database(ready,continuity):
    ready.update(engine=object(),continuity=continuity)
    with pytest.raises(WitnessRejected): issuer.sign_checkpoint_for_verified_refresh(**ready)

@pytest.mark.parametrize('scalar',[17,19,20])
def test_management_key_separation_includes_removed_keys(ready,scalar):
    ready['management_private_key']=ec.derive_private_key(scalar,ec.SECP256R1())
    with pytest.raises(WitnessRejected): issuer.sign_checkpoint_for_verified_refresh(**ready)

@pytest.mark.parametrize('change',['revision','tombstone','window','root','audience'])
def test_continuity_mismatch_never_signs(ready,monkeypatch,change):
    state=json.loads(json.dumps(FIXTURE['state']))
    if change=='revision':state['revision']-=1
    elif change=='tombstone':state['history']=[e for e in state['history'] if not e['removed']]
    elif change=='window':state['history'][0]['jwk']['notAfter']+=1
    else:state[change]='different'
    ready['continuity']=replace(ready['continuity'],state_sha256=commitment(state))
    monkeypatch.setattr(issuer,'_sign_payload',lambda *args:pytest.fail('mismatched continuity signed'))
    with pytest.raises(WitnessRejected):issuer.sign_checkpoint_for_verified_refresh(**ready)

@pytest.mark.parametrize('clock,mono',[([1700000000,1699999999],[1,2]),([1700000000,1700000000,1699999999],[1,2,3]),
    ([1700000000,1700000000,1700000120],[1,2,3]),([1700000000,1700000000,1700000000],[1,2,122]),
    ([1700000000,1700000000,1700000000],[1,2,1]),([True],[1]),([1700000000],[float('nan')])])
def test_clock_expiry_rollback_and_stalls(ready,clock,mono):
    walls,elapsed=iter(clock),iter(mono)
    with pytest.raises(WitnessRejected):issuer.sign_checkpoint_for_verified_refresh(**ready,clock=lambda:next(walls),monotonic=lambda:next(elapsed))

def test_writer_waits_for_signing(ready,monkeypatch):
    signing,release,writing=Event(),Event(),Event();original=issuer._sign_payload
    def held(*args):
        signing.set();assert release.wait(10);return original(*args)
    def started(conn,cursor,statement,parameters,context,executemany):
        if statement.startswith('INSERT INTO sociacl_witness_policy'):writing.set()
    monkeypatch.setattr(issuer,'_sign_payload',held);event.listen(ready['engine'],'before_cursor_execute',started)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=pool.submit(issuer.sign_checkpoint_for_verified_refresh,**ready);assert signing.wait(10)
            removal=pool.submit(install_verified_policy,ready['engine'],9,[])
            try:
                assert writing.wait(10)
                with pytest.raises(TimeoutError):removal.result(timeout=0.2)
            finally:release.set()
            assert verify_response(result.result(timeout=10))['state']['revision']==8
            assert removal.result(timeout=10).revision==9
        with pytest.raises(WitnessRejected):issuer.sign_checkpoint_for_verified_refresh(**ready)
    finally:release.set();event.remove(ready['engine'],'before_cursor_execute',started)

@pytest.mark.parametrize('limit',['MAX_PAYLOAD_BYTES','MAX_ENVELOPE_BYTES','MAX_RESPONSE_BYTES'])
def test_wire_caps(ready,monkeypatch,limit):
    monkeypatch.setattr(issuer,limit,1)
    with pytest.raises(WitnessRejected):issuer.sign_checkpoint_for_verified_refresh(**ready)

def test_signed_fixture_matches_actual_signer(ready):
    fixture=json.loads(Path(__file__).with_name('fixtures').joinpath('sociacl-checkpoint-issued.json').read_text())
    actual=verify_response(issuer.sign_checkpoint_for_verified_refresh(**ready))
    assert verify_response(json.dumps(fixture['response']))==actual
    assert fixture['expected']['root']==FIXTURE['root']
