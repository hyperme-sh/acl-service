"""Protected source callbacks cannot widen retirement signer authority."""
import asyncio
import base64
from dataclasses import replace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from acl_service.allocation_protocol.media_retirement_request import RetirementRequestSigner, RetirementScope, verify_retirement_request
from acl_service.domain.media_retirement import RetirementBinding
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


@pytest.fixture
def setup():
    point=ec.derive_private_key(1,ec.SECP256R1()).public_key().public_numbers()
    x,y=point.x.to_bytes(32),point.y.to_bytes(32)
    owner='.'.join(base64.urlsafe_b64encode(v).rstrip(b'=').decode() for v in (x,y))
    object='media_p_'+(x+y).hex()+'_'+'a'*32
    tenant,issuer,source=map(lambda n:str(UUID(int=n)),(1,2,3))
    key=Ed25519PrivateKey.from_private_bytes(b'\x08'*32)
    signer=RetirementRequestSigner(issuer=issuer,tenant=tenant,source=source,key_id='source',signing_key=key)
    state={'claims':{'tenant':tenant,'object':object,'owner':owner,'command':'a'*64,'issuedAt':100,'expiresAt':130},'error':None,'calls':0}
    class Authority:
        async def _work(self,fn):return fn(lambda:None)
        def prepare_retirement_request(self,t,r,o,*,sign_request,cancel):
            assert (t,r,o)==(tenant,owner,object);cancel();state['calls']+=1
            if state['error']:raise state['error']
            return sign_request(state['claims'])
    return RetirementBinding(tenant,owner,Authority(),signer),object,state,key


@pytest.mark.asyncio
async def test_exact_command_verified_under_storage_domain_and_retry(setup):
    binding,object,state,key=setup
    expected=RetirementScope(binding.signer.issuer,binding.tenant,binding.signer.source,object,binding.reader,'a'*64)
    first=await binding.prepare(object)
    assert verify_retirement_request(first,expected=expected,keys={'source':key.public_key()},now=100).scope==expected
    state['claims'].update(issuedAt=200,expiresAt=230)
    second=await binding.prepare(object)
    assert second!=first
    assert verify_retirement_request(second,expected=expected,keys={'source':key.public_key()},now=200).scope==expected
    assert state['calls']==2


@pytest.mark.asyncio
async def test_scope_shape_and_window_mismatches_refuse(setup):
    binding,object,state,_=setup;original=state['claims'].copy()
    for field,value in [('tenant',str(UUID(int=9))),('object','other'),('owner','other'),('issuedAt',True),('expiresAt',True),('expiresAt',131),('command','bad')]:
        state['claims']={**original,field:value}
        with pytest.raises(AdmissionRejected):await binding.prepare(object)
    for claims in [None,{},dict(original,extra=1)]:
        state['claims']=claims
        with pytest.raises(AdmissionRejected):await binding.prepare(object)
    state['claims']=original
    foreign=replace(binding,tenant=str(UUID(int=9)))
    with pytest.raises(AdmissionRejected):await foreign.prepare(object)
    for value in [None,1,'','a'*257]:
        with pytest.raises(AdmissionRejected):await binding.prepare(value)


@pytest.mark.asyncio
async def test_cancellation_conflict_and_source_refusal_preserved(setup):
    binding,object,state,_=setup
    for error,expected in [(asyncio.CancelledError(),asyncio.CancelledError),(HistoryConflict('changed'),HistoryConflict),(ValueError(),AdmissionRejected),(TimeoutError(),AdmissionRejected)]:
        state['error']=error
        with pytest.raises(expected):await binding.prepare(object)
