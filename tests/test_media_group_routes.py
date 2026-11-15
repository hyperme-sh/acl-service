"""HTTP contracts run in CI; they never contact a deployed service."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.private_wrap_routes import PrivateWrapBinding
from acl_service.interfaces.api.media_group_routes import router

BASE='/acl/sociacl/media/groups/'
SCOPE={'predicate':'same-group','set':'set_group'}
CASES=[
    ('create-view',dict(SCOPE,object='media_anchor')),
    ('create',dict(SCOPE,object='media_anchor',at=100,fence='a'*64,config={})),
    ('create-state',dict(SCOPE,object='media_anchor',config={})),
    ('member-view',dict(SCOPE,member='member',role='member',stated=1)),
    ('member-append',dict(SCOPE,member='member',role='member',at=100,fence='a'*64,row={})),
    ('member-state',dict(SCOPE,member='member',role='member',row={})),
    ('catalog',{'page':0}),
    ('key-view',dict(SCOPE)),
    ('key-append',dict(SCOPE,at=100,fence='a'*64,command={})),
    ('key-state',dict(SCOPE,command={})),
]


@pytest.fixture
def setup():
    tenant=uuid4();actor=SimpleNamespace(sub='fixed',scopes=['acl:media:read','acl:media:write'])
    authority=Mock(group_operation=AsyncMock(return_value={'at':100}))
    store=Mock(tenant=str(tenant));binding=PrivateWrapBinding(str(tenant),'fixed-principal',authority,store)
    app=FastAPI();app.include_router(router)
    app.state.private_wrap_bindings={(tenant,actor.sub):binding}
    app.state.private_wrap_slots=asyncio.Semaphore(2)
    app.state.private_wrap_body_slots={(tenant,actor.sub):asyncio.Semaphore(1)}
    app.state.private_wrap_tenant_slots={tenant:asyncio.Semaphore(1)}
    app.state.rate_limiter=Mock(allow=Mock(return_value=True))
    app.dependency_overrides[get_current_user]=lambda:actor
    app.dependency_overrides[require_matched_tenant]=lambda:tenant
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize('action,body',CASES)
async def test_fixed_binding_exact_body_and_private_response(setup,action,body):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        response=await client.post(BASE+action,json=body)
        assert response.status_code==200
        assert response.headers['cache-control']=='private, no-store'
        s.authority.group_operation.assert_awaited_once_with(action,str(s.tenant),'fixed-principal',body)
        for extra in ({'writer':'attacker'},{'tenant':str(uuid4())},{'epoch':1}):
            assert (await client.post(BASE+action,json={**body,**extra})).status_code==400
        assert s.authority.group_operation.await_count==1


@pytest.mark.asyncio
async def test_authorization_availability_and_bounded_transport(setup):
    s=setup;action,body=CASES[0]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        assert (await client.post(BASE+'unknown',json=body)).status_code==404
        assert (await client.post(BASE+action,content=b'x'*18433,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(BASE+action,json=body,headers={'content-encoding':'gzip'})).status_code==415
        assert (await client.post(BASE+action,content=b'{}')).status_code==415
        for raw in (b'{"predicate":"same-group","predicate":"named-circle"}',b'[]',b'{"v":NaN}',b'\xff'):
            assert (await client.post(BASE+action,content=raw,headers={'content-type':'application/json'})).status_code==400
        s.actor.scopes=['acl:media:write']
        assert (await client.post(BASE+action,json=body)).status_code==403
        s.actor.scopes=['acl:media:read','acl:media:write']
        s.store.tenant=str(uuid4())
        assert (await client.post(BASE+action,json=body)).status_code==403
        s.store.tenant=str(s.tenant)
        s.app.state.rate_limiter.allow.return_value=False
        assert (await client.post(BASE+action,json=body)).status_code==429
        s.app.state.rate_limiter.allow.return_value=True
        s.authority.group_operation=None
        assert (await client.post(BASE+action,json=body)).status_code==503
        s.app.state.private_wrap_bindings=None
        assert (await client.post(BASE+action,json=body)).status_code==503


@pytest.mark.asyncio
@pytest.mark.parametrize('error,status',[(AdmissionRejected('private'),403),(HistoryConflict('private'),409),(ValueError('private'),503),(TimeoutError('private'),503)])
async def test_backend_refusal_never_leaks_details(setup,error,status):
    s=setup;s.authority.group_operation.side_effect=error
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        response=await client.post(BASE+'create-view',json=CASES[0][1])
        assert response.status_code==status
        assert 'private' not in response.text


@pytest.mark.asyncio
async def test_invalid_command_fields_and_busy_capacity_refuse(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for action,body in CASES:
            for key,value in [('predicate','unknown'),('set','bad'),('object',[]),('member',[]),('role','owner'),('stated',True),('at',True),('fence','bad'),('config',[]),('row',[]),('command',[])]:
                if key in body: assert (await client.post(BASE+action,json={**body,key:value})).status_code==400
        await s.app.state.private_wrap_tenant_slots[s.tenant].acquire()
        assert (await client.post(BASE+'create-view',json=CASES[0][1])).status_code==429
        s.app.state.private_wrap_tenant_slots[s.tenant].release()
        s.authority.group_operation.assert_not_awaited()


@pytest.mark.asyncio
async def test_catalog_rejects_invalid_pages(setup):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=setup.app),base_url='https://acl') as client:
        for page in (-1,16,True,0.5,'0',None):
            assert (await client.post(BASE+'catalog',json={'page':page})).status_code==400
    setup.authority.group_operation.assert_not_awaited()


@pytest.mark.asyncio
async def test_group_key_body_limit_is_bounded_without_expanding_other_actions(setup):
    s=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for action in ('key-append','key-state'):
            body=dict(SCOPE,command={'padding':'x'*20000})
            if action=='key-append':body.update(at=100,fence='a'*64)
            assert (await client.post(BASE+action,json=body)).status_code==200
            assert (await client.post(BASE+action,content=b'x'*73729,headers={'content-type':'application/json'})).status_code==413
        assert (await client.post(BASE+'key-view',content=b'x'*18433,headers={'content-type':'application/json'})).status_code==413
