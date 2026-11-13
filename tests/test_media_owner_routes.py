"""Owner HTTP contracts, executed in CI only."""
import asyncio
import base64
import hashlib
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.domain.private_wrap_publication import WrapWritePermit
from acl_service.interfaces.api.private_wrap_routes import PrivateWrapBinding
from acl_service.interfaces.api.media_owner_routes import router


@pytest.fixture
def setup():
    tenant=uuid4();actor=SimpleNamespace(sub='fixed-subject',scopes=['acl:media:write'])
    authority=Mock(owner_view=AsyncMock(return_value={'at':100,'fence':'a'*64}),owner_mutate=AsyncMock(return_value=True))
    store=Mock(tenant=str(tenant));binding=PrivateWrapBinding(str(tenant),'fixed-owner',authority,store)
    app=FastAPI();app.include_router(router)
    app.state.private_wrap_bindings={(tenant,actor.sub):binding}
    app.state.private_wrap_slots=asyncio.Semaphore(2)
    app.state.private_wrap_body_slots={(tenant,actor.sub):asyncio.Semaphore(1)}
    app.state.private_wrap_tenant_slots={tenant:asyncio.Semaphore(1)}
    app.state.rate_limiter=Mock(allow=Mock(return_value=True))
    app.dependency_overrides[get_current_user]=lambda:actor
    app.dependency_overrides[require_matched_tenant]=lambda:tenant
    return SimpleNamespace(**locals())


BASE='/acl/sociacl/media/owner/'
WRITE={'object':'media-object','at':100,'fence':'a'*64,'operation':'grant','payload':{'proof':'signed'}}


@pytest.mark.asyncio
async def test_owner_catalog_uses_fixed_subject_and_bounded_page_only(setup):
    s=setup;s.authority.owner_catalog=AsyncMock(return_value={'at':100,'objects':['private-object'],'nextPage':1})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        response=await client.post(BASE+'catalog',json={'page':0})
        assert response.status_code==200
        assert response.json()=={'at':100,'objects':['private-object'],'nextPage':1}
        assert response.headers['cache-control']=='private, no-store'
        s.authority.owner_catalog.assert_awaited_once_with(str(s.tenant),'fixed-owner',0)
        for body in [{},{'page':True},{'page':-1},{'page':16},{'page':0,'writer':'attacker'},{'page':0,'object':'foreign'}]:
            assert (await client.post(BASE+'catalog',json=body)).status_code==400
        assert s.authority.owner_catalog.await_count==1


@pytest.mark.asyncio
async def test_owner_status_view_only_selects_a_recipient_of_the_fixed_owner(setup):
    s=setup;s.authority.owner_status_view=AsyncMock(return_value={'status':{'accessor':'recipient'}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        body={'object':'media-object','reader':'recipient'}
        response=await client.post(BASE+'status-view',json=body)
        assert response.status_code==200
        assert response.json()=={'status':{'accessor':'recipient'}}
        s.authority.owner_status_view.assert_awaited_once_with(str(s.tenant),'fixed-owner','media-object','recipient')
        for changes in [{'reader':[]},{'reader':'bad reader'},{'writer':'attacker'},{'at':100}]:
            assert (await client.post(BASE+'status-view',json={**body,**changes})).status_code==400
        assert s.authority.owner_status_view.await_count==1


@pytest.mark.asyncio
async def test_fixed_owner_binding_and_exact_write_fence(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        view=await client.post(BASE+'view',json={'object':'media-object'})
        write=await client.post(BASE+'mutate',json=WRITE)
    assert view.status_code==write.status_code==200
    assert view.json()=={'at':100,'fence':'a'*64}
    assert write.json()=={'accepted':True}
    assert write.headers['cache-control']=='private, no-store'
    s.authority.owner_view.assert_awaited_once_with(str(s.tenant),'fixed-owner','media-object')
    s.authority.owner_mutate.assert_awaited_once_with(str(s.tenant),'fixed-owner','media-object',100,'a'*64,'grant',{'proof':'signed'})
    s.store.assert_not_called()


@pytest.mark.asyncio
async def test_client_writer_and_provisioning_are_not_transport_operations(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for body in [{**WRITE,'writer':'attacker'},{**WRITE,'operation':'provision'},{**WRITE,'operation':'policy'},
                     {**WRITE,'at':True},{**WRITE,'at':-1},{**WRITE,'fence':'invalid'},
                     {**WRITE,'payload':[]},{**WRITE,'object':'contains space'},[]]:
            assert (await client.post(BASE+'mutate',json=body)).status_code==400
        assert (await client.post(BASE+'view',json={'object':'media-object','reader':'attacker'})).status_code==400
        assert (await client.post(BASE+'provision',json={})).status_code==404
        assert (await client.post(BASE+'view',content=b'{"object":"a","object":"b"}',headers={'content-type':'application/json'})).status_code==400
    s.authority.owner_mutate.assert_not_awaited();s.authority.owner_view.assert_not_awaited()


@pytest.mark.asyncio
async def test_binding_permission_and_disabled_source_refuse(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        s.actor.scopes=['acl:media:read']
        assert (await client.post(BASE+'view',json={'object':'media-object'})).status_code==403
        s.actor.scopes=['acl:media:write'];s.actor.sub='other'
        assert (await client.post(BASE+'view',json={'object':'media-object'})).status_code==403
        s.app.state.private_wrap_bindings=None
        assert (await client.post(BASE+'view',json={'object':'media-object'})).status_code==503
    s.authority.owner_view.assert_not_awaited()


@pytest.mark.asyncio
async def test_conflict_denial_and_rate_refusals_do_not_leak_source_details(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for error,status in [(HistoryConflict('private path'),409),(AdmissionRejected('private policy'),403),(TimeoutError(),503)]:
            s.authority.owner_mutate.side_effect=error
            response=await client.post(BASE+'mutate',json=WRITE)
            assert response.status_code==status
            assert 'private path' not in response.text and 'private policy' not in response.text
        s.app.state.rate_limiter.allow.return_value=False
        assert (await client.post(BASE+'mutate',json=WRITE)).status_code==429


@pytest.mark.asyncio
async def test_body_limits_encoding_and_shared_tenant_capacity(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        assert (await client.post(BASE+'view',content=b'x'*2049,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(BASE+'mutate',content=b'x'*81921,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(BASE+'view',json={'object':'media-object'},headers={'content-encoding':'gzip'})).status_code==415
        await s.app.state.private_wrap_tenant_slots[s.tenant].acquire()
        assert (await client.post(BASE+'view',json={'object':'media-object'})).status_code==429
        s.app.state.private_wrap_tenant_slots[s.tenant].release()
    s.authority.owner_view.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_publication_reserves_then_writes_and_commits(setup):
    s=setup;payload=b'private encrypted material';digest=hashlib.sha256(payload).hexdigest()
    permit=WrapWritePermit(str(s.tenant),'fixed-owner','media-object',digest,digest,len(payload),'held',int(time.time())+2)
    s.authority.prepare_wrap_write=AsyncMock(return_value=permit)
    s.authority.commit_wrap_write=AsyncMock(return_value=True)
    s.store.create_or_reconcile=AsyncMock(return_value=digest)
    body={'object':'media-object','at':100,'fence':'a'*64,'metadata':{'record':digest},'wrapBase64':base64.b64encode(payload).decode()}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        response=await client.post(BASE+'publish-wrap',json=body)
        assert response.status_code==200
        assert response.json()=={'record':digest,'digest':digest}
        s.authority.prepare_wrap_write.assert_awaited_once_with(str(s.tenant),'fixed-owner','media-object',100,'a'*64,{'record':digest},digest,len(payload))
        s.store.create_or_reconcile.assert_awaited_once_with(digest,payload)
        s.authority.commit_wrap_write.assert_awaited_once_with(permit)
        for changes in [{'wrapBase64':'!'},{'wrapBase64':''},{'metadata':[]},{'writer':'attacker'}]:
            assert (await client.post(BASE+'publish-wrap',json={**body,**changes})).status_code==400
        s.authority.prepare_wrap_write.side_effect=AdmissionRejected('quota')
        assert (await client.post(BASE+'publish-wrap',json=body)).status_code==403
        assert s.store.create_or_reconcile.await_count==1
