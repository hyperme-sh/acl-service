"""One-shot private gateway exchange; untrusted replies remain signed inputs."""
from types import SimpleNamespace
from uuid import UUID
import httpx
import pytest
from acl_service.infrastructure.media_allocation_client import AllocationClient,AllocationUnavailable

TENANT=str(UUID(int=1))
SCOPE=SimpleNamespace(tenant=TENANT,object='media_object',owner='owner',ownership_digest='a'*64)


@pytest.mark.asyncio
async def test_bounded_request_and_exact_response_without_retry():
    calls=[]
    def handle(request):
        calls.append(request)
        assert request.headers['x-api-key']=='private-fixture-key'
        assert request.headers['x-tenant-id']==TENANT
        assert request.url.path=='/api/v1/storage/allocations/issue'
        return httpx.Response(200,stream=httpx.ByteStream(b'{"signed":"grant"}'))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        client=AllocationClient('https://storage.example',TENANT,'private-fixture-key',client=http)
        assert await client.issue(SCOPE,b'proof')==b'{"signed":"grant"}'
    assert len(calls)==1


@pytest.mark.asyncio
@pytest.mark.parametrize('status,headers,body',[(302,{'location':'https://foreign.example'},b''),
    (409,{},b'conflict'),(500,{},b'secret'),(200,{},b''),(200,{},b'x'*4097),
    (200,{'content-encoding':'gzip'},b'x'),(200,{'content-length':'bad'},b'x'),
    (200,{'content-length':'2'},b'x')])
async def test_bad_gateway_reply_refuses_without_retry(status,headers,body):
    calls=[]
    def handle(request):calls.append(request);return httpx.Response(status,headers=headers,stream=httpx.ByteStream(body))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        client=AllocationClient('https://storage.example',TENANT,'key',client=http)
        with pytest.raises(AllocationUnavailable,match='unavailable'):
            await client.issue(SCOPE,b'proof')
    assert len(calls)==1


def test_invalid_origin_tenant_or_credential_refuses():
    for origin,tenant,key in [('http://storage.example',TENANT,'key'),('https://storage.example/path',TENANT,'key'),
                             ('https://user@storage.example',TENANT,'key'),('https://storage.example',str(UUID(int=0)),'key'),
                             ('https://storage.example',TENANT,'key\n')]:
        with pytest.raises(ValueError):AllocationClient(origin,tenant,key)
