"""Storage cleanup acknowledgements are bounded and match the accepted command."""
import base64
import json
from uuid import UUID
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from acl_service.allocation_protocol.media_retirement_request import RetirementScope
from acl_service.infrastructure.media_allocation_client import AllocationClient,AllocationUnavailable


def scope():
    point=ec.derive_private_key(1,ec.SECP256R1()).public_key().public_numbers()
    x,y=point.x.to_bytes(32),point.y.to_bytes(32)
    owner='.'.join(base64.urlsafe_b64encode(v).rstrip(b'=').decode() for v in (x,y))
    return RetirementScope(str(UUID(int=2)),str(UUID(int=1)),str(UUID(int=3)),
        'media_p_'+(x+y).hex()+'_'+'a'*32,owner,'b'*64)


@pytest.mark.asyncio
async def test_retirement_transport_exact_scope_and_explicit_retry():
    expected=scope();calls=[];result={'accepted':True,'command':expected.command,'cleanup':'complete'}
    def handle(request):
        calls.append(request)
        assert request.url.path=='/api/v1/storage/media/retire'
        assert request.headers['x-tenant-id']==expected.tenant
        assert request.headers['x-api-key']=='fixture'
        assert json.loads(request.content)=={'object':expected.object,'owner':expected.owner,'command':expected.command,'request':base64.b64encode(b'proof').decode()}
        return httpx.Response(503 if len(calls)==1 else 200,stream=httpx.ByteStream(json.dumps(result).encode()))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        client=AllocationClient('https://storage.example',expected.tenant,'fixture',client=http)
        with pytest.raises(AllocationUnavailable):await client.retire(expected,b'proof')
        assert len(calls)==1
        assert await client.retire(expected,b'proof')==result
        assert len(calls)==2


@pytest.mark.asyncio
async def test_pending_changed_or_malformed_ack_never_claims_complete():
    expected=scope();valid={'accepted':True,'command':expected.command,'cleanup':'complete'}
    for result in [None,[],{},dict(valid,cleanup='pending'),dict(valid,accepted=1),dict(valid,command='c'*64),dict(valid,extra=True)]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,stream=httpx.ByteStream(json.dumps(result).encode())))) as http:
            client=AllocationClient('https://storage.example',expected.tenant,'fixture',client=http)
            with pytest.raises(AllocationUnavailable):await client.retire(expected,b'proof')
            with pytest.raises(AllocationUnavailable):await client.retire(expected,b'')
            foreign=AllocationClient('https://storage.example',str(UUID(int=9)),'fixture',client=http)
            with pytest.raises(AllocationUnavailable):await foreign.retire(expected,b'proof')
