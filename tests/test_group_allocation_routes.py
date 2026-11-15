"""Allocation transport authorization and cancellation contracts for CI."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user,require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict
from acl_service.interfaces.api.group_allocation_routes import router,connected_allocate


@pytest.fixture
def setup():
    tenant=uuid4();user=SimpleNamespace(sub='owner-session',scopes=['acl:media:write'])
    binding=SimpleNamespace(tenant=str(tenant),client=SimpleNamespace(tenant=str(tenant)),allocate=AsyncMock(return_value={'accepted':True}))
    app=FastAPI();app.include_router(router)
    app.state.group_allocation_bindings={(tenant,user.sub):binding}
    app.state.group_allocation_slots=asyncio.Semaphore(2)
    app.state.group_allocation_body_slots={(tenant,user.sub):asyncio.Semaphore(1)}
    app.state.group_allocation_tenant_slots={tenant:asyncio.Semaphore(1)}
    app.state.rate_limiter=Mock(allow=Mock(return_value=True))
    app.dependency_overrides[get_current_user]=lambda:user
    app.dependency_overrides[require_matched_tenant]=lambda:tenant
    return SimpleNamespace(**locals())


RECORD={'set':'set_group','predicate':'same-group'}
PATH='/acl/sociacl/media/groups/allocate'


@pytest.mark.asyncio
async def test_exact_subject_scope_body_and_disabled_binding(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        reply=await client.post(PATH,json=RECORD)
        assert reply.status_code==200 and reply.headers['cache-control']=='private, no-store'
        s.binding.allocate.assert_awaited_once_with(RECORD)
        for body in [{},[],{**RECORD,'policy':{}},{**RECORD,'source':'attacker'}]:
            assert (await client.post(PATH,json=body)).status_code==400
        assert (await client.post(PATH,content=b'x'*2049,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(PATH,content=b'{}')).status_code==415
        s.user.scopes=[]
        assert (await client.post(PATH,json=RECORD)).status_code==403
        s.user.scopes=['acl:media:write'];s.app.state.rate_limiter.allow.return_value=False
        assert (await client.post(PATH,json=RECORD)).status_code==429
        s.app.state.group_allocation_bindings=None
        assert (await client.post(PATH,json=RECORD)).status_code==503


@pytest.mark.asyncio
@pytest.mark.parametrize('error,status',[(HistoryConflict(),409),(AdmissionRejected(),403),(TimeoutError(),503)])
async def test_refusals_do_not_retry_or_expose_details(setup,error,status):
    s=setup;s.binding.allocate.side_effect=error
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        assert (await client.post(PATH,json=RECORD)).status_code==status
    assert s.binding.allocate.await_count==1


@pytest.mark.asyncio
async def test_disconnect_cancels_pending_authority_work():
    cancelled=asyncio.Event();started=asyncio.Event()
    async def allocate(record):
        started.set()
        try:await asyncio.Event().wait()
        finally:cancelled.set()
    async def disconnected():
        await started.wait()
        return True
    with pytest.raises(TimeoutError):
        await connected_allocate(SimpleNamespace(is_disconnected=disconnected),SimpleNamespace(allocate=allocate),RECORD)
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_assembled_application_reaches_allocation_before_group_action(setup,monkeypatch):
    import importlib
    from starlette.middleware.base import BaseHTTPMiddleware
    module=importlib.import_module('acl_service.app')
    class NoDatabase(BaseHTTPMiddleware):
        async def dispatch(self,request,call_next):return await call_next(request)
    monkeypatch.setattr(module,'AclServiceDbMiddleware',NoDatabase)
    s=setup
    app=module.create_app(signed_store_bindings={},statement_bindings={},delegation_bindings={},
        private_wrap_bindings={},media_allocation_bindings={},group_allocation_bindings={(s.tenant,s.user.sub):s.binding})
    app.state.rate_limiter=s.app.state.rate_limiter
    app.dependency_overrides[get_current_user]=lambda:s.user
    app.dependency_overrides[require_matched_tenant]=lambda:s.tenant
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://acl') as client:
        response=await client.post('/api/v1'+PATH,json=RECORD)
    assert response.status_code==200
    s.binding.allocate.assert_awaited_once_with(RECORD)
