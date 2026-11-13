"""ASGI transport contracts, executed in CI only."""
import asyncio
import base64
from dataclasses import replace
import hashlib
from types import SimpleNamespace
import time
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

from fastapi import FastAPI, HTTPException
import httpx
import pytest

from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.private_wrap_delivery import WrapReadPermit
from acl_service.interfaces.api.private_wrap_routes import router, PrivateWrapBinding


@pytest.fixture
def setup():
    tenant = uuid4()
    actor = SimpleNamespace(sub='token-subject', scopes=['acl:media:read'])
    payload = b'private encrypted wrap'
    permit = WrapReadPermit(str(tenant), 'enrolled-reader', 'media-object', 'a'*64,
        hashlib.sha256(payload).hexdigest(), 7, 'b'*64, 'current-reader-epub', 'c'*64,
        int(time.time()) + 60)
    authority = Mock(authorize_read=AsyncMock(return_value=permit), commit_delivery=AsyncMock(return_value=True))
    store = Mock(tenant=str(tenant), read=AsyncMock(return_value=payload))
    binding = PrivateWrapBinding(str(tenant), permit.reader, authority, store)
    app = FastAPI()
    app.include_router(router)
    app.state.private_wrap_bindings = {(tenant, actor.sub): binding}
    app.state.private_wrap_slots = asyncio.Semaphore(2)
    app.state.private_wrap_body_slots = {(tenant, actor.sub):asyncio.Semaphore(1)}
    app.state.private_wrap_tenant_slots = {tenant:asyncio.Semaphore(1)}
    app.state.rate_limiter = Mock(allow=Mock(return_value=True))
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[require_matched_tenant] = lambda: tenant
    return SimpleNamespace(**locals())


PATH = '/acl/sociacl/media/read-wrap'


@pytest.mark.asyncio
async def test_committed_context_and_private_bytes_share_one_decision(setup):
    s = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app), base_url='https://owner') as client:
        response = await client.post(PATH, json={'object':'media-object'})
    assert response.status_code == 200
    assert response.json() == {'context': {'object':'media-object', 'epoch':7, 'revisionId':'b'*64},
        'readerEpub':'current-reader-epub', 'expiresAt':s.permit.expires_at,
        'wrapBase64':base64.b64encode(s.payload).decode()}
    assert response.headers['cache-control'] == 'private, no-store'
    assert response.headers['x-content-type-options'] == 'nosniff'
    s.authority.authorize_read.assert_awaited_once_with(str(s.tenant),'enrolled-reader','media-object')
    s.authority.commit_delivery.assert_awaited_once_with(s.permit)


@pytest.mark.asyncio
async def test_binding_permissions_tenant_and_capacity_refuse_before_fetch(setup):
    s = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app), base_url='https://owner') as client:
        async def refused(status):
            response = await client.post(PATH,json={'object':'media-object'})
            assert response.status_code == status
            assert response.headers['cache-control'] == 'private, no-store'
        s.app.state.private_wrap_bindings = None
        await refused(503)
        s.app.state.private_wrap_bindings = {(s.tenant,s.actor.sub):s.binding}
        s.actor.sub='other'
        await refused(403)
        s.actor.sub='token-subject'
        s.app.state.private_wrap_bindings[(s.tenant,s.actor.sub)] = replace(s.binding,tenant=str(uuid4()))
        await refused(403)
        s.app.state.private_wrap_bindings[(s.tenant,s.actor.sub)] = s.binding
        s.store.tenant = str(uuid4())
        await refused(403)
        s.store.tenant = str(s.tenant)
        s.actor.scopes=['acl:statements:read']
        await refused(403)
        s.actor.scopes=['acl:media:read']
        s.app.state.rate_limiter.allow.return_value=False
        await refused(429)
        s.app.state.rate_limiter.allow.return_value=True
        s.app.state.private_wrap_slots=asyncio.Semaphore(0)
        await refused(429)
    s.authority.authorize_read.assert_not_called()
    s.store.read.assert_not_called()


@pytest.mark.asyncio
async def test_request_cannot_supply_context_reader_or_provider_location(setup):
    s = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app), base_url='https://owner') as client:
        for body in [b'{"object":"media-object","object":"other"}', b'[]', b'null', b'{"object":true}',
                     b'{"object":""}', b'{"object":"a b"}', b'{"object":NaN}', b'\xff', b'['*1000,
                     b'{"object":"media-object","reader":"other"}',
                     b'{"object":"media-object","epoch":7}', b'{"object":"x","url":"https://evil"}']:
            assert (await client.post(PATH,content=body,headers={'Content-Type':'application/json'})).status_code == 400
        assert (await client.post(PATH,content=b'x'*2049,headers={'Content-Type':'application/json'})).status_code == 413
        assert (await client.post(PATH,content=b'{}')).status_code == 415
        assert (await client.post(PATH,json={'object':'media-object'},headers={'Content-Encoding':'gzip'})).status_code == 415
    s.authority.authorize_read.assert_not_called()
    assert s.app.state.private_wrap_slots._value == 2


@pytest.mark.asyncio
async def test_revocation_expiry_wrong_reader_and_provider_errors_do_not_return_material(setup):
    s = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app), base_url='https://owner') as client:
        for permit in [replace(s.permit,reader='other'), replace(s.permit,expires_at=0)]:
            s.authority.authorize_read.return_value=permit
            assert (await client.post(PATH,json={'object':'media-object'})).status_code == 403
        s.authority.authorize_read.return_value=s.permit
        s.authority.commit_delivery.return_value=False
        response=await client.post(PATH,json={'object':'media-object'})
        assert response.status_code == 403 and 'wrapBase64' not in response.text
        s.store.read.side_effect=RuntimeError('private URL and credentials')
        response=await client.post(PATH,json={'object':'media-object'})
        assert response.json() == {'detail':'Private wrap access refused'}
    assert s.app.state.private_wrap_slots._value == 2


@pytest.mark.asyncio
async def test_body_deadline_and_cancellation_release_slots(setup):
    s = setup
    async def stalled():
        yield b'{'
        await asyncio.sleep(10)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://owner') as client:
        response=await client.post(PATH,content=stalled(),headers={'Content-Type':'application/json'})
        assert response.status_code == 503
        assert s.app.state.private_wrap_slots._value == 2
        s.authority.authorize_read.side_effect=asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await client.post(PATH,json={'object':'media-object'})
    assert s.app.state.private_wrap_slots._value == 2
    s.store.read.assert_not_called()


@pytest.mark.asyncio
async def test_transport_requires_authenticated_dependencies(setup):
    s = setup
    def missing_user(): raise HTTPException(401,'Authentication required')
    s.app.dependency_overrides[get_current_user]=missing_user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://owner') as client:
        assert (await client.post(PATH,json={'object':'media-object'})).status_code == 401
    s.authority.authorize_read.assert_not_called()


@pytest.mark.asyncio
async def test_slow_subject_body_cannot_hold_other_tenants_backend_capacity(setup):
    s=setup
    other=uuid4()
    other_permit=replace(s.permit,tenant=str(other))
    other_authority=Mock(authorize_read=AsyncMock(return_value=other_permit),commit_delivery=AsyncMock(return_value=True))
    other_store=Mock(tenant=str(other),read=AsyncMock(return_value=s.payload))
    s.app.state.private_wrap_bindings[(other,s.actor.sub)]=PrivateWrapBinding(str(other),s.permit.reader,other_authority,other_store)
    s.app.state.private_wrap_body_slots[(other,s.actor.sub)]=asyncio.Semaphore(1)
    s.app.state.private_wrap_tenant_slots[other]=asyncio.Semaphore(1)
    started=asyncio.Event()
    async def stalled():
        yield b'{'
        started.set()
        await asyncio.sleep(10)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://owner') as client:
        work=asyncio.create_task(client.post(PATH,content=stalled(),headers={'Content-Type':'application/json'}))
        try:
            await asyncio.wait_for(started.wait(),1)
            assert s.app.state.private_wrap_slots._value == 2
            assert (await client.post(PATH,json={'object':'media-object'})).status_code == 429
            s.app.dependency_overrides[require_matched_tenant]=lambda:other
            assert (await client.post(PATH,json={'object':'media-object'})).status_code == 200
            assert (await work).status_code == 503
        finally:
            if not work.done():
                work.cancel()
                with pytest.raises(asyncio.CancelledError): await work
    s.authority.authorize_read.assert_not_called()
    assert s.app.state.private_wrap_body_slots[(s.tenant,s.actor.sub)]._value == 1
    assert s.app.state.private_wrap_slots._value == 2


@pytest.mark.asyncio
async def test_one_tenant_cannot_take_both_backend_slots(setup):
    s=setup
    started=asyncio.Event()
    release=asyncio.Event()
    async def held(*args):
        started.set()
        await release.wait()
        return s.permit
    s.authority.authorize_read.side_effect=held
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://owner') as client:
        work=asyncio.create_task(client.post(PATH,json={'object':'media-object'}))
        try:
            await asyncio.wait_for(started.wait(),1)
            assert s.app.state.private_wrap_slots._value == 1
            assert (await client.post(PATH,json={'object':'media-object'})).status_code == 429
        finally: release.set()
        assert (await work).status_code == 200
    assert s.app.state.private_wrap_slots._value == 2
    assert s.app.state.private_wrap_tenant_slots[s.tenant]._value == 1
