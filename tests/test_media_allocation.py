"""The coordinator must recheck authority after storage, without retrying writes."""
import asyncio
import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from acl_service.allocation_protocol.media_allocation_grant import canonical_message
from acl_service.domain.media_allocation import AllocationBinding,canonical
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict


@pytest.fixture
def binding():
    point=ec.derive_private_key(1,ec.SECP256R1()).public_key().public_numbers()
    x,y=point.x.to_bytes(32),point.y.to_bytes(32)
    owner='.'.join(base64.urlsafe_b64encode(v).rstrip(b'=').decode() for v in (x,y))
    record={'object':'media_p_'+(x+y).hex()+'_'+'a'*32,'owner':owner,'issuedAt':100,'sig':'fixture'}
    tenant,issuer,source=map(lambda n:str(UUID(int=n)),(1,2,3))
    key=Ed25519PrivateKey.from_private_bytes(b'\x08'*32)
    state={'changed':False,'consumed':False,'calls':[],'foreign':False}
    class Authority:
        async def _work(self,fn):return fn(lambda:None)
        def prepare_allocation_request(self,*args,**kwargs):
            state['calls'].append('prepare');return b'authenticated request'
        def consume_allocation(self,*args,**kwargs):
            state['calls'].append('consume')
            if state['changed']:raise HistoryConflict('owner rotated')
            kwargs['verify_grant'](110)
            state['consumed']=True;return True
    async def issue(scope,request):
        state['calls'].append('issue')
        claims={**scope.claims(),'version':1,'allocation':str(UUID(int=4)),'issuedAt':100,'expiresAt':200}
        if state['foreign']:claims['tenant']=str(UUID(int=9))
        signature=base64.urlsafe_b64encode(key.sign(canonical_message('issuer',claims))).rstrip(b'=').decode()
        return canonical({'keyId':'issuer','claims':claims,'signature':signature})
    client=SimpleNamespace(issue=AsyncMock(side_effect=issue))
    value=AllocationBinding(tenant,owner,Authority(),client,None,issuer,source,{},1000,{'issuer':key.public_key()})
    return value,record,state


@pytest.mark.asyncio
async def test_current_authority_and_exact_signed_scope_required_after_exchange(binding):
    value,record,state=binding
    assert await value.allocate(record)=={'object':record['object'],'accepted':True}
    assert state['calls']==['prepare','issue','consume'] and state['consumed']
    state.update(changed=True,consumed=False)
    with pytest.raises(HistoryConflict):await value.allocate(record)
    assert not state['consumed']
    state.update(changed=False,foreign=True)
    with pytest.raises(AdmissionRejected):await value.allocate(record)
    assert not state['consumed']


@pytest.mark.asyncio
async def test_transport_failure_cancellation_and_invalid_input_do_not_consume(binding):
    value,record,state=binding
    for error in [TimeoutError(),asyncio.CancelledError()]:
        value.client.issue.side_effect=error
        with pytest.raises(asyncio.CancelledError if isinstance(error,asyncio.CancelledError) else AdmissionRejected):
            await value.allocate(record)
        assert not state['consumed']
    assert value.client.issue.await_count==2
    for bad in [None,{'bad':float('inf')},{**record,'sig':'x'*2049},{**record,'object':'foreign'}]:
        with pytest.raises(AdmissionRejected):await value.allocate(bad)
    assert value.client.issue.await_count==2
