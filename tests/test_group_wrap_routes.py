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
    authority=SimpleNamespace(group_item_epoch_view=AsyncMock(return_value={'at':100,'snapshot':{}}),group_item_grant_state=AsyncMock(return_value={'at':100,'state':'applied','frozen':False}),
                              group_item_grant_view=AsyncMock(return_value={'at':100}),
                              append_group_item_grant=AsyncMock(return_value=True),
                              group_item_authority_view=AsyncMock(return_value={'at':100,'projection':None,'fence':'c'*64}),
                              group_wrap_view=AsyncMock(return_value={'fence':'a'*64}),
                              group_item_view=AsyncMock(return_value={'fence':'b'*64,'expiresAt':102}))
    binding=SimpleNamespace(tenant=str(tenant),reader='fixed-reader',authority=authority,store=SimpleNamespace(tenant=str(tenant)))
    app=FastAPI();app.include_router(routes.router);app.include_router(routes.owner_router);app.include_router(routes.item_byte_router)
    app.state.private_wrap_bindings=None
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
async def test_item_view_binds_owner_and_scope_without_storage(setup):
    s=setup;body={**RECORD,'object':'media_owner_item'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-view',json=body)
        assert result.status_code==200 and result.headers['cache-control']=='private, no-store'
        assert result.json()=={'fence':'b'*64,'expiresAt':102}
        s.authority.group_item_view.assert_awaited_once_with(str(s.tenant),'fixed-reader',body['object'],RECORD['predicate'],RECORD['set'])
        s.publish.assert_not_awaited();s.read.assert_not_awaited()
        s.authority.group_item_view.reset_mock()
        for bad in [RECORD,{**body,'owner':'attacker'},{**body,'at':100},{**body,'object':[]},
                    {**body,'object':''},{**body,'object':'with space'},{**body,'object':'x'*513}]:
            assert (await client.post(PATH+'item-view',json=bad)).status_code==400
        s.user.scopes=['acl:media:read']
        assert (await client.post(PATH+'item-view',json=body)).status_code==403
        s.authority.group_item_view.assert_not_awaited()
        s.user.scopes=['acl:media:write']
        s.authority.group_item_view.side_effect=AdmissionRejected('private source detail')
        result=await client.post(PATH+'item-view',json=body)
        assert result.status_code==403 and 'private source detail' not in result.text

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
        private_wrap_bindings={(s.tenant,s.user.sub):s.binding},media_allocation_bindings={},group_allocation_bindings={},
        group_wrap_bindings={(s.tenant,s.user.sub):s.binding})
    app.state.rate_limiter=s.app.state.rate_limiter
    app.dependency_overrides[get_current_user]=lambda:s.user
    app.dependency_overrides[require_matched_tenant]=lambda:s.tenant
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://acl') as client:
        assert (await client.post('/api/v1'+PATH+'wrap-view',json=RECORD)).status_code==200
        assert (await client.post('/api/v1'+PATH+'item-view',json={**RECORD,'object':'media_owner_item'})).status_code==200
        assert (await client.post('/api/v1'+PATH+'item-epoch-view',json={**RECORD,'object':'media_owner_item'})).status_code==200
        assert (await client.post('/api/v1'+PATH+'item-authority-view',json={'object':'media_owner_item'})).status_code==200
        assert (await client.post('/api/v1'+PATH+'item-grant-view',json={**RECORD,'object':'media_owner_item','reader':'reader','withdraw':False})).status_code==200
        assert (await client.post('/api/v1'+PATH+'item-grant-append',json={**RECORD,'object':'media_owner_item','at':100,'fence':'a'*64,'payload':{}})).status_code==200
        scope={**RECORD,'object':'media_owner_item'}
        for action,method,body,response in [
            ('item-epoch-append','append_group_item_epoch',{**scope,'at':100,'fence':'a'*64,'payload':{}},True),
            ('item-epoch-state','group_item_epoch_state',{**scope,'payload':{}},{'state':'applied'}),
            ('item-status-view','group_item_status_view',{**scope,'reader':'recipient'},{'status':{}}),
            ('item-status-append','append_group_item_status',{**scope,'reader':'recipient','at':100,'fence':'a'*64,'payload':{}},True),
            ('item-status-state','group_item_status_state',{**scope,'reader':'recipient','payload':{}},{'state':'applied'}),
            ('item-wrap-view','group_item_publication_view',{**scope,'reader':'recipient'},{'metadata':{}}),
        ]:
            call=AsyncMock(return_value=response);setattr(s.authority,method,call)
            result=await client.post('/api/v1'+PATH+action,json=body)
            assert result.status_code==200 and result.headers['cache-control']=='private, no-store'
            call.assert_awaited_once()
            assert call.call_args.args[:3]==(str(s.tenant),'fixed-reader',scope['object'])
            app.state.group_wrap_bindings=None
            assert (await client.post('/api/v1'+PATH+action,json=body)).status_code==503
            app.state.group_wrap_bindings={(s.tenant,s.user.sub):s.binding}
        from acl_service.domain.group_item_delivery import DeliveredGroupItemWrap
        publish=AsyncMock(return_value='d'*64)
        read=AsyncMock(return_value=DeliveredGroupItemWrap(b'opaque',scope['object'],scope['predicate'],scope['set'],2,'a'*64,'b'*64,3,'c'*64,'e'*64,102))
        monkeypatch.setattr(routes,'publish_group_item_wrap',publish);monkeypatch.setattr(routes,'deliver_group_item_wrap',read)
        body={**scope,'reader':'anchor','at':100,'fence':'a'*64,'metadata':{'digest':'d'*64},'payload':base64.b64encode(b'opaque').decode()}
        result=await client.post('/api/v1'+PATH+'item-wrap-publish',json=body)
        assert result.status_code==200 and result.json()=={'digest':'d'*64}
        publish.assert_awaited_once_with(s.authority,s.binding.store,str(s.tenant),'fixed-reader',scope['object'],scope['predicate'],scope['set'],
            'anchor',100,'a'*64,body['metadata'],b'opaque')
        result=await client.post('/api/v1'+PATH+'item-wrap-read',json=scope)
        assert result.status_code==200 and result.json()['payload']==body['payload']
        assert result.headers['cache-control']=='private, no-store'
        read.assert_awaited_once_with(s.authority,s.binding.store,str(s.tenant),'fixed-reader',scope['object'],scope['predicate'],scope['set'])
    s.authority.group_item_authority_view.assert_awaited_once_with(str(s.tenant),'fixed-reader','media_owner_item')
    s.authority.group_wrap_view.assert_awaited_once()
    s.authority.group_item_view.assert_awaited_once()


@pytest.mark.asyncio
async def test_item_authority_view_selects_scope_only_from_protected_source(setup):
    s=setup;body={'object':'media_owner_item'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-authority-view',json=body)
        assert result.status_code==200 and result.headers['cache-control']=='private, no-store'
        assert result.json()=={'at':100,'projection':None,'fence':'c'*64}
        s.authority.group_item_authority_view.assert_awaited_once_with(str(s.tenant),'fixed-reader',body['object'])
        s.publish.assert_not_awaited();s.read.assert_not_awaited()
        s.authority.group_item_authority_view.reset_mock()
        for bad in [[],{}, {**body,**RECORD},{**body,'owner':'attacker'},
                    {**body,'reader':'attacker'},{**body,'at':100},{'object':[]},
                    {'object':''},{'object':'with space'},{'object':'x'*513}]:
            assert (await client.post(PATH+'item-authority-view',json=bad)).status_code==400
        s.user.scopes=['acl:media:read']
        assert (await client.post(PATH+'item-authority-view',json=body)).status_code==403
        s.authority.group_item_authority_view.assert_not_awaited()
        s.user.scopes=['acl:media:write']
        s.authority.group_item_authority_view.side_effect=AdmissionRejected('private group members')
        result=await client.post(PATH+'item-authority-view',json=body)
        assert result.status_code==403 and 'private group members' not in result.text


@pytest.mark.asyncio
async def test_group_item_grants_bind_owner_validate_bodies_and_sanitize_refusals(setup):
    s=setup;view={**RECORD,'object':'media_owner_item','reader':'recipient','withdraw':False}
    append={**RECORD,'object':view['object'],'at':100,'fence':'a'*64,'payload':{'claims':{},'proof':{}}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        assert (await client.post(PATH+'item-grant-view',json=view)).json()=={'at':100}
        s.authority.group_item_grant_view.assert_awaited_once_with(str(s.tenant),'fixed-reader',view['object'],RECORD['predicate'],RECORD['set'],'recipient',False)
        assert (await client.post(PATH+'item-grant-append',json=append)).json()=={'accepted':True}
        s.authority.append_group_item_grant.assert_awaited_once_with(str(s.tenant),'fixed-reader',view['object'],RECORD['predicate'],RECORD['set'],100,'a'*64,append['payload'])
        for action,body,patches in [('item-grant-view',view,[{'reader':[]},{'reader':''},{'withdraw':1},{'owner':'other'}]),
            ('item-grant-append',append,[{'at':True},{'fence':'bad'},{'payload':[]},{'owner':'other'}])]:
            for patch in patches:assert (await client.post(PATH+action,json={**body,**patch})).status_code==400
            s.user.scopes=['acl:media:read']
            assert (await client.post(PATH+action,json=body)).status_code==403
            s.user.scopes=['acl:media:write']
        assert (await client.post(PATH+'item-grant-append',content=b'x'*8193,headers={'content-type':'application/json'})).status_code==413
        s.authority.append_group_item_grant.return_value=False
        assert (await client.post(PATH+'item-grant-append',json=append)).status_code==403
        s.authority.append_group_item_grant.side_effect=HistoryConflict('private journal')
        result=await client.post(PATH+'item-grant-append',json=append)
        assert result.status_code==409 and 'private journal' not in result.text
        s.publish.assert_not_awaited();s.read.assert_not_awaited()


@pytest.mark.asyncio
async def test_group_item_grant_reconciliation_is_fixed_owner_and_read_only(setup):
    s=setup;body={**RECORD,'object':'media_owner_item','payload':{'claims':{},'proof':{}}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-grant-state',json=body)
        assert result.status_code==200 and result.json()=={'at':100,'state':'applied','frozen':False}
        s.authority.group_item_grant_state.assert_awaited_once_with(str(s.tenant),'fixed-reader',body['object'],RECORD['predicate'],RECORD['set'],body['payload'])
        assert (await client.post(PATH+'item-grant-state',json={**body,'payload':[]})).status_code==400
        s.user.scopes=['acl:media:read']
        assert (await client.post(PATH+'item-grant-state',json=body)).status_code==403
        s.authority.append_group_item_grant.assert_not_awaited()


@pytest.mark.asyncio
async def test_item_epoch_plan_is_subject_bound_and_read_only(setup):
    s=setup;body={**RECORD,'object':'media_owner_item'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-epoch-view',json=body)
        assert result.status_code==200 and result.headers['cache-control']=='private, no-store'
        s.authority.group_item_epoch_view.assert_awaited_once_with(str(s.tenant),'fixed-reader',body['object'],body['predicate'],body['set'])
        s.publish.assert_not_awaited();s.read.assert_not_awaited()
        for patch in [{'object':[]},{'owner':'other'},{'at':100},{'predicate':'direct'},{'set':'bad'}]:
            assert (await client.post(PATH+'item-epoch-view',json={**body,**patch})).status_code==400
        s.user.scopes=['acl:media:read']
        assert (await client.post(PATH+'item-epoch-view',json=body)).status_code==403
        s.user.scopes=['acl:media:write']
        s.authority.group_item_epoch_view.side_effect=AdmissionRejected('private details')
        result=await client.post(PATH+'item-epoch-view',json=body)
        assert result.status_code==403 and 'private details' not in result.text


@pytest.mark.asyncio
async def test_owner_routes_refuse_missing_runtime_bindings(setup):
    s=setup;s.app.state.group_wrap_bindings=None
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for action in ('item-epoch-append','item-epoch-state','item-status-view','item-status-append','item-status-state','item-wrap-view'):
            assert (await client.post(PATH+action,json={})).status_code==503


@pytest.mark.asyncio
async def test_owner_commands_bind_the_session_owner_in_ci(setup):
    s=setup
    scope={**RECORD,'object':'media_owner_item'}
    operations=[
        ('item-epoch-append','append_group_item_epoch',{**scope,'at':100,'fence':'a'*64,'payload':{}},True,{'accepted':True}),
        ('item-epoch-state','group_item_epoch_state',{**scope,'payload':{}},{'state':'applied'},{'state':'applied'}),
        ('item-status-view','group_item_status_view',{**scope,'reader':'recipient'},{'status':{}},{'status':{}}),
        ('item-status-append','append_group_item_status',{**scope,'reader':'recipient','at':100,'fence':'a'*64,'payload':{}},True,{'accepted':True}),
        ('item-status-state','group_item_status_state',{**scope,'reader':'recipient','payload':{}},{'state':'applied'},{'state':'applied'}),
        ('item-wrap-view','group_item_publication_view',{**scope,'reader':'recipient'},{'metadata':{}},{'metadata':{}}),
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        for action,method,body,response,expected in operations:
            call=AsyncMock(return_value=response);setattr(s.authority,method,call)
            result=await client.post(PATH+action,json=body)
            assert result.status_code==200 and result.json()==expected
            assert result.headers['cache-control']=='private, no-store'
            args=(str(s.tenant),'fixed-reader',scope['object'],scope['predicate'],scope['set'])
            if 'reader' in body:args+=('recipient',)
            if action.endswith('append'):args+=(100,'a'*64,{})
            elif action.endswith('state'):args+=({},)
            call.assert_awaited_once_with(*args)
            patches=[{'owner':'spoofed'},{'object':[]},{'set':'bad'}]
            if 'payload' in body:patches.append({'payload':[]})
            if 'reader' in body:patches.extend([{'reader':''},{'reader':[]}])
            if 'at' in body:patches.extend([{'at':True},{'fence':'bad'}])
            for patch in patches:assert (await client.post(PATH+action,json={**body,**patch})).status_code==400
            s.user.scopes=['acl:media:read']
            assert (await client.post(PATH+action,json=body)).status_code==403
            s.user.scopes=['acl:media:write'];call.side_effect=AdmissionRejected('secret detail')
            refused=await client.post(PATH+action,json=body)
            assert refused.status_code==403 and 'secret detail' not in refused.text
            call.side_effect=HistoryConflict('secret detail')
            assert (await client.post(PATH+action,json=body)).status_code==409
            call.side_effect=None
            if action.endswith('append'):
                call.return_value=1
                assert (await client.post(PATH+action,json=body)).status_code==403
            limit=270336 if action.startswith('item-epoch-') else 8192 if action.endswith(('append','state')) else 2048
            assert (await client.post(PATH+action,content=b'x'*(limit+1),headers={'content-type':'application/json'})).status_code==413
        s.publish.assert_not_awaited();s.read.assert_not_awaited()


@pytest.mark.asyncio
async def test_group_item_byte_routes_require_runtime_configuration(setup):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=setup.app),base_url='https://acl') as client:
        for action in ('item-wrap-publish','item-wrap-read'):
            assert (await client.post(PATH+action,json={})).status_code==503


@pytest.mark.asyncio
async def test_group_item_bytes_use_private_media_binding_and_fixed_reader(setup,monkeypatch):
    from acl_service.domain.group_item_delivery import DeliveredGroupItemWrap,GroupItemDeliveryRejected
    s=setup
    binding=SimpleNamespace(tenant=str(s.tenant),reader='media-reader',authority=object(),store=SimpleNamespace(tenant=str(s.tenant)))
    s.app.state.private_wrap_bindings={(s.tenant,s.user.sub):binding}
    s.app.state.private_wrap_slots=asyncio.Semaphore(2)
    s.app.state.private_wrap_body_slots={(s.tenant,s.user.sub):asyncio.Semaphore(1)}
    s.app.state.private_wrap_tenant_slots={s.tenant:asyncio.Semaphore(1)}
    publish=AsyncMock(return_value='d'*64)
    read=AsyncMock(return_value=DeliveredGroupItemWrap(b'opaque','media_owner_item',RECORD['predicate'],RECORD['set'],2,'a'*64,'b'*64,3,'c'*64,'e'*64,102))
    monkeypatch.setattr(routes,'publish_group_item_wrap',publish);monkeypatch.setattr(routes,'deliver_group_item_wrap',read)
    scope={**RECORD,'object':'media_owner_item'}
    body={**scope,'reader':'anchor-reader','at':100,'fence':'a'*64,'metadata':{'digest':'d'*64},'payload':base64.b64encode(b'opaque').decode()}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-wrap-publish',json=body)
        assert result.status_code==200 and result.json()=={'digest':'d'*64}
        publish.assert_awaited_once_with(binding.authority,binding.store,str(s.tenant),'media-reader',scope['object'],scope['predicate'],scope['set'],
            'anchor-reader',100,'a'*64,body['metadata'],b'opaque')
        result=await client.post(PATH+'item-wrap-read',json=scope)
        assert result.status_code==200 and result.json()['payload']==body['payload']
        assert result.json()['item_epoch']==2 and result.json()['group_epoch']==3
        assert result.headers['cache-control']=='private, no-store'
        read.assert_awaited_once_with(binding.authority,binding.store,str(s.tenant),'media-reader',scope['object'],scope['predicate'],scope['set'])
        for action,request_body,call in [('item-wrap-publish',body,publish),('item-wrap-read',scope,read)]:
            call.reset_mock()
            for patch in [{'owner':'spoofed'},{'object':[]},{'predicate':'direct'},{'set':'bad'}]:
                assert (await client.post(PATH+action,json={**request_body,**patch})).status_code==400
            s.user.scopes=['acl:media:read' if action.endswith('publish') else 'acl:media:write']
            assert (await client.post(PATH+action,json=request_body)).status_code==403
            s.user.scopes=['acl:media:read','acl:media:write'];call.assert_not_awaited()
            await s.app.state.private_wrap_tenant_slots[s.tenant].acquire()
            assert (await client.post(PATH+action,json=request_body)).status_code==429
            s.app.state.private_wrap_tenant_slots[s.tenant].release();call.assert_not_awaited()
            call.side_effect=GroupItemDeliveryRejected('private detail')
            refused=await client.post(PATH+action,json=request_body)
            assert refused.status_code==403 and 'private detail' not in refused.text
            call.side_effect=HistoryConflict('private detail')
            assert (await client.post(PATH+action,json=request_body)).status_code==409
            call.side_effect=None
            s.app.state.private_wrap_bindings=None
            assert (await client.post(PATH+action,json=request_body)).status_code==503
            s.app.state.private_wrap_bindings={}
            assert (await client.post(PATH+action,json=request_body)).status_code==403
            s.app.state.private_wrap_bindings={(s.tenant,s.user.sub):binding}
        for patch in [{'reader':''},{'reader':[]},{'at':True},{'fence':'bad'},{'metadata':[]},{'payload':'!bad'}]:
            assert (await client.post(PATH+'item-wrap-publish',json={**body,**patch})).status_code==400
        assert (await client.post(PATH+'item-wrap-read',json={**scope,'reader':'spoofed'})).status_code==400
        for action,limit in [('item-wrap-read',2048),('item-wrap-publish',92160)]:
            assert (await client.post(PATH+action,content=b'x'*(limit+1),headers={'content-type':'application/json'})).status_code==413
    s.publish.assert_not_awaited();s.read.assert_not_awaited()


@pytest.mark.asyncio
async def test_prepared_owner_maintenance_route_is_uninstalled_and_write_scoped(setup,monkeypatch):
    from acl_service.domain.group_owner_wrap import DeliveredOwnerWrap,OwnerWrapRejected
    from acl_service.app import create_app
    s=setup
    # Production assembly remains unchanged; mounting below is contract-local only.
    assert not any(getattr(route,'path','').endswith('/item-owner-wrap-read') for route in create_app().routes)
    assert not any(getattr(route,'path','').endswith('/item-owner-wrap-read') for route in s.app.routes)
    s.app.include_router(routes.owner_wrap_router)
    binding=SimpleNamespace(tenant=str(s.tenant),reader='fixed-owner',authority=object(),store=SimpleNamespace(tenant=str(s.tenant)))
    s.app.state.private_wrap_bindings={(s.tenant,s.user.sub):binding}
    s.app.state.private_wrap_slots=asyncio.Semaphore(2)
    s.app.state.private_wrap_body_slots={(s.tenant,s.user.sub):asyncio.Semaphore(1)}
    s.app.state.private_wrap_tenant_slots={s.tenant:asyncio.Semaphore(1)}
    read=AsyncMock(return_value=DeliveredOwnerWrap(b'opaque','media_owner_item',RECORD['predicate'],RECORD['set'],1,'a'*64,'owner-e','b'*64,'c'*64,102))
    monkeypatch.setattr(routes,'deliver_owner_wrap',read)
    body={**RECORD,'object':'media_owner_item'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app),base_url='https://acl') as client:
        result=await client.post(PATH+'item-owner-wrap-read',json=body)
        assert result.status_code==200 and result.json()['payload']==base64.b64encode(b'opaque').decode()
        assert result.headers['cache-control']=='private, no-store' and 'fence' not in result.json()
        read.assert_awaited_once_with(binding.authority,binding.store,str(s.tenant),'fixed-owner',body['object'],body['predicate'],body['set'])
        read.reset_mock()
        for patch in [{'owner':'spoofed'},{'reader':'spoofed'},{'object':[]},{'set':'bad'}]:
            assert (await client.post(PATH+'item-owner-wrap-read',json={**body,**patch})).status_code==400
        s.user.scopes=['acl:media:read']
        assert (await client.post(PATH+'item-owner-wrap-read',json=body)).status_code==403
        read.assert_not_awaited();s.user.scopes=['acl:media:write']
        read.side_effect=OwnerWrapRejected('private detail')
        result=await client.post(PATH+'item-owner-wrap-read',json=body)
        assert result.status_code==403 and 'private detail' not in result.text
        read.side_effect=HistoryConflict('changed')
        assert (await client.post(PATH+'item-owner-wrap-read',json=body)).status_code==409
        read.side_effect=None;s.app.state.private_wrap_bindings=None
        assert (await client.post(PATH+'item-owner-wrap-read',json=body)).status_code==503
    s.publish.assert_not_awaited();s.read.assert_not_awaited()
