"""Real PostgreSQL snapshot serialization; no management authorization claim."""
import base64
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Event

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import event, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from controlplane_db.models import SociaclWitnessPolicy
from acl_service.infrastructure.witness_policy_repo import PostgresWitnessPolicyWriter
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure import witness_policy_snapshot as snapshots
from acl_service.infrastructure.witness_policy_repo import install_verified_policy, read_policy
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_policy_ingest import ROOT_KEY, AUDIENCE, bundle, document, sign
from test_witness_policy_repo import engine, key  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401


def install(engine, signed):
    return ingest.install_signed_policy(PostgresWitnessPolicyWriter(engine), *signed, ROOT_KEY.public_key(), AUDIENCE)


def snapshot(engine, signed):
    return snapshots.locked_complete_policy_snapshot(engine, *signed, ROOT_KEY.public_key(), AUDIENCE)


def corrupt(engine, change):
    with Session(engine) as session, session.begin():
        row = session.get(SociaclWitnessPolicy, 1)
        history = json.loads(json.dumps(row.history))
        change(row, history)
        row.history = history
        flag_modified(row, "history")  # bool/int equality must not suppress corruption writes.


def test_snapshot_preserves_narrowed_and_removed_history_and_exact_policy(engine):
    d = document(); signed = bundle(d); install(engine, signed)
    d['revision'] = 2; d['jwks']['keys'][0]['notBefore'] += 1; d['jwks']['keys'][0]['notAfter'] -= 1
    narrowed = json.loads(json.dumps(d['jwks']['keys'][0])); install(engine, bundle(d))
    d['revision'] = 3; d['jwks'] = {'keys': [key('new', 8)[0].jwk()]}
    payload = json.dumps(d, indent=2).encode() + b'\n'; signed = (payload, sign(payload)); install(engine, signed)
    with snapshot(engine, signed) as result:
        state = json.loads(result.state_json)
        assert state['revision'] == 3
        assert state['history'][0] == {'jwk': narrowed, 'removed': True}
        assert state['history'][1]['removed'] is False
        envelope = json.loads(result.policy_json)
        assert base64.urlsafe_b64decode(envelope['payload'] + '==') == payload
        assert base64.urlsafe_b64decode(envelope['signature'] + '==') == signed[1]
        with pytest.raises(FrozenInstanceError):
            result.state_json = '{}'
    engine.dispose()
    with snapshot(engine, signed) as reopened:
        assert reopened == result


@pytest.mark.parametrize('case', ['missing-active', 'removed-active', 'window', 'material', 'bad-point',
    'root-reuse', 'duplicate-material', 'unknown-entry', 'bad-boolean', 'wrong-kid', 'bad-window-type', 'active-schema'])
def test_corrupt_history_or_registry_never_leaves_snapshot(engine, case):
    signed = bundle(); install(engine, signed)
    def damage(row, history):
        kid = next(iter(history)); entry = history[kid]
        if case == 'missing-active': history.clear()
        elif case == 'removed-active': entry['removed'] = True
        elif case == 'window': entry['jwk']['notAfter'] += 1
        elif case == 'material': entry['jwk'].update({k: v for k, v in key('new', 8)[0].jwk().items() if k in ('x', 'y')})
        elif case == 'bad-point': entry['jwk']['x'] = 'a' * 43
        elif case == 'root-reuse':
            history['root'] = {'jwk': key('root', ROOT_KEY.private_numbers().private_value)[0].jwk(), 'removed': True}
        elif case == 'duplicate-material':
            history['alias'] = {'jwk': {**entry['jwk'], 'kid': 'alias'}, 'removed': True}
        elif case == 'unknown-entry': entry['extra'] = True
        elif case == 'bad-boolean': entry['removed'] = 0
        elif case == 'wrong-kid': entry['jwk']['kid'] = 'different'
        elif case == 'bad-window-type': entry['jwk']['notBefore'] = True
        elif case == 'active-schema': row.jwks = {**row.jwks, 'extra': True}
    corrupt(engine, damage)
    with pytest.raises(WitnessRejected):
        with snapshot(engine, signed): pytest.fail('corrupt snapshot yielded')


@pytest.mark.parametrize('case', ['absent', 'older', 'future', 'conflicting'])
def test_snapshot_requires_exact_installed_registry_and_revision(engine, case):
    d = document(); signed = bundle(d)
    if case != 'absent': install(engine, signed)
    if case == 'older': install(engine, bundle({**d, 'revision': 2, 'jwks': {'keys': []}}))
    if case == 'future': signed = bundle({**d, 'revision': 2})
    if case == 'conflicting': signed = bundle({**d, 'jwks': {'keys': []}})
    with pytest.raises(WitnessRejected):
        with snapshot(engine, signed): pytest.fail('uninstalled snapshot yielded')


def test_bad_signature_never_connects():
    signed = bundle()
    with pytest.raises(WitnessRejected):
        with snapshot(object(), (signed[0] + b' ', signed[1])): pytest.fail('bad signature yielded')


def test_policy_writer_waits_until_snapshot_consumer_finishes(engine):
    signed = bundle(); install(engine, signed)
    writing = Event()
    def started(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO sociacl_witness_policy'): writing.set()
    event.listen(engine, 'before_cursor_execute', started)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with snapshot(engine, signed) as before:
                future = pool.submit(install_verified_policy, engine, 2, [])
                assert writing.wait(10)
                with pytest.raises(TimeoutError): future.result(timeout=0.2)
                assert json.loads(before.state_json)['revision'] == 1
            assert future.result(timeout=10).revision == 2
        with pytest.raises(WitnessRejected):
            with snapshot(engine, signed): pytest.fail('old snapshot after removal')
    finally: event.remove(engine, 'before_cursor_execute', started)


def test_consumer_failure_releases_lock_without_mutating_policy(engine):
    signed = bundle(); install(engine, signed); before = read_policy(engine)
    with pytest.raises(RuntimeError, match='consumer failed'):
        with snapshot(engine, signed): raise RuntimeError('consumer failed')
    assert read_policy(engine) == before
    assert install_verified_policy(engine, 2, []).revision == 2


@pytest.mark.parametrize('stage', ['wait', 'build', 'consumer'])
def test_expiry_rechecked_after_lock_and_before_release(engine, monkeypatch, stage):
    d = document(); d.update(issuedAt=999, expiresAt=1001)
    monkeypatch.setattr(ingest.time, 'time', lambda: 1000)
    signed = bundle(d); install(engine, signed)
    times = iter({'wait': [1000, 1001], 'build': [1000, 1000, 1001], 'consumer': [1000, 1000, 1000, 1001]}[stage])
    monkeypatch.setattr(ingest.time, 'time', lambda: next(times))
    yielded = False
    with pytest.raises(WitnessRejected):
        with snapshot(engine, signed): yielded = True
    assert yielded is (stage == 'consumer')


def test_complete_history_matches_shared_typescript_rust_state_fixture(engine, monkeypatch):
    fixture = json.loads(Path(__file__).with_name('fixtures').joinpath('sociacl-policy-snapshot.json').read_text())
    monkeypatch.setattr(ingest.time, 'time', lambda: fixture['now'])
    root = ec.derive_private_key(17, ec.SECP256R1()).public_key()
    envelope = json.loads(fixture['policy'])
    decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    signed = (decode(envelope['payload']), decode(envelope['signature']))
    state = fixture['state']
    # Authenticated lifecycle fixture supplies the trusted database history; a
    # live policy alone cannot reconstruct its already-removed key.
    with Session(engine) as session, session.begin():
        session.add(SociaclWitnessPolicy(id=1, revision=state['revision'], jwks=state['jwks'],
            history={entry['jwk']['kid']: entry for entry in state['history']}))
    with snapshots.locked_complete_policy_snapshot(engine, *signed, root, state['audience']) as result:
        assert json.loads(result.state_json) == state
        assert json.loads(result.policy_json) == envelope
        assert json.loads(result.state_json)['root'] == fixture['root']


def test_snapshot_size_and_history_caps_do_not_prune(engine, monkeypatch):
    signed = bundle(); install(engine, signed)
    with snapshot(engine, signed) as valid: size = len(valid.state_json.encode('utf-8'))
    monkeypatch.setattr(snapshots, 'MAX_STATE_BYTES', size)
    with snapshot(engine, signed) as exact: assert exact == valid
    monkeypatch.setattr(snapshots, 'MAX_STATE_BYTES', size - 1)
    with pytest.raises(WitnessRejected):
        with snapshot(engine, signed): pytest.fail('oversized state yielded')
    monkeypatch.setattr(snapshots, 'MAX_STATE_BYTES', 2097152)
    corrupt(engine, lambda row, history: history.update({str(i): {} for i in range(1025)}))
    with pytest.raises(WitnessRejected):
        with snapshot(engine, signed): pytest.fail('oversized history yielded')

def test_snapshot_accepts_all_1024_removed_keys_without_pruning(engine):
    d = document(); d['jwks'] = {'keys': []}; signed = bundle(d); install(engine, signed)
    history = {f'old-{i:04}': {'jwk': key(f'old-{i:04}', 100 + i)[0].jwk(), 'removed': True} for i in range(1024)}
    corrupt(engine, lambda row, saved: saved.update(history))
    with snapshot(engine, signed) as result:
        state = json.loads(result.state_json)
        assert len(state['history']) == 1024
        assert all(entry['removed'] for entry in state['history'])
        assert state['jwks'] == {'keys': []}


def test_utf8_order_is_stable_for_non_bmp_identifiers(engine):
    d = document(); d['jwks'] = {'keys': [key('\U00010000', 8)[0].jwk(), key('\ue000', 9)[0].jwk()]}
    signed = bundle(d); install(engine, signed)
    with snapshot(engine, signed) as result:
        state = json.loads(result.state_json)
        assert [entry['jwk']['kid'] for entry in state['history']] == ['\ue000', '\U00010000']
        assert [entry['kid'] for entry in state['jwks']['keys']] == ['\ue000', '\U00010000']


def test_waiting_reader_rechecks_new_committed_revision(engine):
    signed = bundle(); install(engine, signed)
    waiting = Event()
    def started(conn, cursor, statement, parameters, context, executemany):
        if 'FOR SHARE' in statement: waiting.set()
    def read():
        with snapshot(engine, signed): return True
    event.listen(engine, 'before_cursor_execute', started)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with Session(engine) as session, session.begin():
                row = session.scalars(select(SociaclWitnessPolicy).where(SociaclWitnessPolicy.id == 1).with_for_update()).one()
                future = pool.submit(read)
                assert waiting.wait(10)
                with pytest.raises(TimeoutError): future.result(timeout=0.2)
                row.revision = 2; row.jwks = {'keys': []}
                row.history = {kid: {**entry, 'removed': True} for kid, entry in row.history.items()}
            with pytest.raises(WitnessRejected): future.result(timeout=10)
    finally: event.remove(engine, 'before_cursor_execute', started)
