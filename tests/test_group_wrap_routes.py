"""Authenticated group wrap HTTP contracts, executed in CI only."""
import asyncio
import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user,require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict
from acl_service.domain.group_wrap import DeliveredGroupWrap,GroupWrapRejected
from acl_service.interfaces.api import group_wrap_routes as routes

RECORD={'predicate':'same-group','set':'set_p_'+'a'*128+'_'+'b'*32}
PATH='/acl/sociacl/media/groups/'

@pytest.fixture
def setup(monkeypatch):
    tenant=uuid4();user=SimpleNamespace(sub='session',scopes=['acl:media:read','acl:media:write'])
    authority=SimpleNamespace(group_wrap_view=AsyncMock(return_value={'fence':'a'*64}))
    binding=SimpleNamespace(tenant=str(tenant),reader='fixed-reader',authority=authority,store=SimpleNamespace(tenant=str(tenant)))
    app=FastAPI();app.include_router(routes.router)
    app.state.group_wrap_bindings={(tenant,user.sub):binding}
    app.state.group_wrap_slots=asyncio.Semaphore(2)
    app.state.group_wrap_body_slots={(tenant,user.sub):asyncio.Semaphore(1)}
    app.state.group_wrap_tenant_slots={tenant:asyncio.Semaphore(1)}
    app.state.rate_limiter=Mock(allow=Mock(return_value=True))
    app.dependency_overrides[get_current_user]=lambda:user
    app.dependency_overrides[require_matched_tenant]=lambda:tenant
    publish=AsyncMock(return_value='d'*64)
    read=AsyncMock(return_value=DeliveredGroupWrap(b'opaque','same-group',RECORD['set'],1,'a'*64,'epub','b'*64,123))
    monkeypatch.setattr(routes,'publish_group_wrap',publish);monkeypatch.setattr(routes,'deliver_group_wrap',read)
    return SimpleNamespace(**locals())

@pytest.mark.asyncio
async def test_subject_bound_view_publication_and_read(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'wrap-view',json=RECORD)
        assert result.status_code==200 and result.headers['cache-control']=='private, no-store'
        assert s.authority.group_wrap_view.call_args.args[:2]==(str(s.tenant),'fixed-reader')
        body={**RECORD,'at':100,'fence':'a'*64,'metadata':{},'payload':base64.b64encode(b'opaque').decode()}
        assert (await client.post(PATH+'wrap-publish',json=body)).json()=={'digest':'d'*64}
        assert s.publish.call_args.args[2:4]==(str(s.tenant),'fixed-reader')
        assert s.publish.call_args.args[-1]==b'opaque'
        result=await client.post(PATH+'wrap-read',json=RECORD)
        assert result.status_code==200 and result.json()['payload']==body['payload']
        for action in ('wrap-view','wrap-publish','wrap-read'):
            s.user.scopes=[]
            assert (await client.post(PATH+action,json=body if action=='wrap-publish' else RECORD)).status_code==403
        s.user.scopes=['acl:media:read'];s.app.state.group_wrap_bindings=None
        assert (await client.post(PATH+'wrap-read',json=RECORD)).status_code==503

@pytest.mark.asyncio
async def test_invalid_input_limits_and_capacity(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for body in [{},[],{**RECORD,'reader':'attacker'},{**RECORD,'set':'wrong'},{**RECORD,'predicate':[]}]:
            assert (await client.post(PATH+'wrap-view',json=body)).status_code==400
        for payload in ['!', '', 'YR==',base64.b64encode(b'x'*65537).decode()]:
            body={**RECORD,'at':100,'fence':'a'*64,'metadata':{},'payload':payload}
            assert (await client.post(PATH+'wrap-publish',json=body)).status_code==400
        assert (await client.post(PATH+'wrap-read',content=b'x'*2049,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(PATH+'wrap-read',content=b'{}')).status_code==415
        slot=s.app.state.group_wrap_tenant_slots[s.tenant]
        await slot.acquire()
        assert (await client.post(PATH+'wrap-read',json=RECORD)).status_code==429
        slot.release();s.app.state.rate_limiter.allow.return_value=False
        assert (await client.post(PATH+'wrap-read',json=RECORD)).status_code==429

@pytest.mark.asyncio
@pytest.mark.parametrize('error,status',[(HistoryConflict(),409),(AdmissionRejected(),403),(GroupWrapRejected(),403),(TimeoutError(),503)])
async def test_sanitized_refusals(setup,error,status):
    s=setup;s.read.side_effect=error
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        assert (await client.post(PATH+'wrap-read',json=RECORD)).status_code==status
    assert s.read.await_count==1

@pytest.mark.asyncio
async def test_disconnect_cancels_work(setup):
    s=setup;started=asyncio.Event();cancelled=asyncio.Event()
    async def pending(*args):
        started.set()
        try:await asyncio.Event().wait()
        finally:cancelled.set()
    async def disconnected():await started.wait();return True
    s.read.side_effect=pending
    with pytest.raises(TimeoutError):
        await routes.connected(SimpleNamespace(is_disconnected=disconnected),'wrap-read',s.binding,RECORD)
    assert cancelled.is_set()

@pytest.mark.asyncio
async def test_assembled_routes_precede_generic_group_action(setup,monkeypatch):
    import importlib
    from starlette.middleware.base import BaseHTTPMiddleware
    module=importlib.import_module('acl_service.app')
    class NoDatabase(BaseHTTPMiddleware):
        async def dispatch(self,request,call_next):return await call_next(request)
    monkeypatch.setattr(module,'AclServiceDbMiddleware',NoDatabase)
    s=setup
    app=module.create_app(signed_store_bindings={},statement_bindings={},delegation_bindings={},
        private_wrap_bindings={},media_allocation_bindings={},group_allocation_bindings={},
        group_wrap_bindings={(s.tenant,s.user.sub):s.binding})
    app.state.rate_limiter=s.app.state.rate_limiter
    app.dependency_overrides[get_current_user]=lambda:s.user
    app.dependency_overrides[require_matched_tenant]=lambda:s.tenant
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://acl') as client:
        assert (await client.post('/api/v1'+PATH+'wrap-view',json=RECORD)).status_code==200
    s.authority.group_wrap_view.assert_awaited_once()
