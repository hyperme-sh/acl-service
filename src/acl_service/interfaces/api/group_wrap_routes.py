"""Subject-bound group wraps with bounded input and disconnect cancellation."""
import asyncio
import base64
from dataclasses import asdict
import json
import re
import time
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.domain.group_wrap import GroupWrapRejected, publish_group_wrap, deliver_group_wrap
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, capacity, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router=APIRouter(prefix='/acl/sociacl/media/groups',tags=['SociACL'])
# Owner commands share the authenticated group binding and admission limits.
owner_router=APIRouter(prefix='/acl/sociacl/media/groups',tags=['SociACL'])
ITEM_ACTIONS={'item-view','item-epoch-view','item-epoch-append','item-epoch-state',
    'item-grant-view','item-grant-append','item-grant-state','item-status-view','item-status-append','item-status-state','item-wrap-view'}
APPEND_ACTIONS={'item-grant-append','item-epoch-append','item-status-append'}
STATE_ACTIONS={'item-grant-state','item-epoch-state','item-status-state'}
READER_ACTIONS={'item-grant-view','item-status-view','item-status-append','item-status-state','item-wrap-view'}



async def execute(action,binding,body):
    if action=='item-authority-view':
        return await binding.authority.group_item_authority_view(binding.tenant,binding.reader,body['object'])
    args=(binding.tenant,binding.reader,body['predicate'],body['set'])
    if action=='item-epoch-view':
        return await binding.authority.group_item_epoch_view(args[0],args[1],body['object'],args[2],args[3])
    if action=='item-epoch-state':
        return await binding.authority.group_item_epoch_state(args[0],args[1],body['object'],args[2],args[3],body['payload'])
    if action=='item-epoch-append':
        result=await binding.authority.append_group_item_epoch(args[0],args[1],body['object'],args[2],args[3],body['at'],body['fence'],body['payload'])
        if result is not True:raise AdmissionRejected('group item epoch refused')
        return {'accepted':True}
    if action=='item-status-view':
        return await binding.authority.group_item_status_view(args[0],args[1],body['object'],args[2],args[3],body['reader'])
    if action=='item-status-state':
        return await binding.authority.group_item_status_state(args[0],args[1],body['object'],args[2],args[3],body['reader'],body['payload'])
    if action=='item-status-append':
        result=await binding.authority.append_group_item_status(args[0],args[1],body['object'],args[2],args[3],body['reader'],body['at'],body['fence'],body['payload'])
        if result is not True:raise AdmissionRejected('group item status refused')
        return {'accepted':True}
    if action=='item-wrap-view':
        return await binding.authority.group_item_publication_view(args[0],args[1],body['object'],args[2],args[3],body['reader'])
    if action=='item-grant-state':
        return await binding.authority.group_item_grant_state(args[0],args[1],body['object'],args[2],args[3],body['payload'])
    if action=='item-grant-view':
        return await binding.authority.group_item_grant_view(args[0],args[1],body['object'],args[2],args[3],body['reader'],body['withdraw'])
    if action=='item-grant-append':
        result=await binding.authority.append_group_item_grant(args[0],args[1],body['object'],args[2],args[3],body['at'],body['fence'],body['payload'])
        if result is not True:raise AdmissionRejected('group item grant refused')
        return {'accepted':True}
    if action=='item-view':
        return await binding.authority.group_item_view(args[0],args[1],body['object'],args[2],args[3])
    if action=='wrap-view':
        return await binding.authority.group_wrap_view(args[0],args[1],int(time.time()),args[2],args[3])
    if action=='wrap-publish':
        digest=await publish_group_wrap(binding.authority,binding.store,*args,body['at'],body['fence'],body['metadata'],body['payload'])
        return {'digest':digest}
    result=asdict(await deliver_group_wrap(binding.authority,binding.store,*args))
    result['payload']=base64.b64encode(result['payload']).decode('ascii')
    return result


async def connected(request,action,binding,body):
    async def disconnected():
        while not await request.is_disconnected():await asyncio.sleep(0.05)
    work=asyncio.create_task(execute(action,binding,body))
    monitor=asyncio.create_task(disconnected())
    try:
        done,_=await asyncio.wait((work,monitor),return_when=asyncio.FIRST_COMPLETED)
        if monitor in done:raise TimeoutError()
        return await work
    finally:
        work.cancel();monitor.cancel()
        await asyncio.gather(work,monitor,return_exceptions=True)


def parse_body(data,action):
    body=json.loads(data,object_pairs_hook=_unique_fields,parse_constant=_invalid_constant)
    if action=='item-authority-view':
        if (type(body) is not dict or set(body)!={'object'} or type(body['object']) is not str
                or re.fullmatch(r'[\x21-\x7e]{1,512}',body['object']) is None):raise ValueError()
        return body
    expected={'predicate','set'}
    if action in ITEM_ACTIONS:expected.add('object')
    if action in READER_ACTIONS:expected.add('reader')
    if action=='item-grant-view':expected.add('withdraw')
    if action in APPEND_ACTIONS:expected|={'at','fence','payload'}
    if action in STATE_ACTIONS:expected.add('payload')
    if action=='wrap-publish':expected|={'at','fence','metadata','payload'}
    if (type(body) is not dict or set(body)!=expected or body['predicate'] not in ('same-group','named-circle')
            or type(body['set']) is not str or re.fullmatch(r'set_p_[0-9a-f]{128}_[0-9a-f]{32}',body['set']) is None):raise ValueError()
    if action in ITEM_ACTIONS and (type(body['object']) is not str
            or re.fullmatch(r'[\x21-\x7e]{1,512}',body['object']) is None):raise ValueError()
    if action in STATE_ACTIONS and type(body['payload']) is not dict:raise ValueError()
    if action in READER_ACTIONS and (type(body['reader']) is not str or not 1<=len(body['reader'])<=1024):raise ValueError()
    if action=='item-grant-view' and type(body['withdraw']) is not bool:raise ValueError()
    if action in APPEND_ACTIONS and (type(body['at']) is not int or not 0<=body['at']<=9007199254740991 or
            type(body['fence']) is not str or re.fullmatch('[0-9a-f]{64}',body['fence']) is None or type(body['payload']) is not dict):raise ValueError()
    if action=='wrap-publish':
        if (type(body['at']) is not int or not 0<=body['at']<=9007199254740991
                or type(body['fence']) is not str or re.fullmatch('[0-9a-f]{64}',body['fence']) is None
                or type(body['metadata']) is not dict or type(body['payload']) is not str):raise ValueError()
        payload=base64.b64decode(body['payload'],validate=True)
        if not 1<=len(payload)<=65536 or base64.b64encode(payload).decode('ascii')!=body['payload']:raise ValueError()
        body['payload']=payload
    return body


async def operation(action,request,tenant,user):
    bindings=request.app.state.group_wrap_bindings
    if bindings is None:raise refused(503,'Group wraps unavailable')
    binding=bindings.get((tenant,user.sub))
    scope='acl:media:read' if action=='wrap-read' else 'acl:media:write'
    if binding is None or binding.tenant!=str(tenant) or binding.store.tenant!=str(tenant) or scope not in user.scopes:
        raise refused(403,'Group wrap access refused')
    if not request.app.state.rate_limiter.allow(tenant,user.sub):raise refused(429,'Rate limit exceeded')
    if (request.headers.get('content-type','').split(';')[0]!='application/json'
            or request.headers.get('content-encoding','identity')!='identity'):raise refused(415,'Expected uncompressed JSON')
    try:
        async with asyncio.timeout(5), capacity(request.app.state.group_wrap_body_slots[(tenant,user.sub)]):
            data=bytearray();limit=270336 if action in ('item-epoch-append','item-epoch-state') else 92160 if action=='wrap-publish' else 8192 if action in APPEND_ACTIONS|STATE_ACTIONS else 2048
            async with asyncio.timeout(1):
                async for chunk in request.stream():
                    if len(data)+len(chunk)>limit:raise refused(413,'Request too large')
                    data.extend(chunk)
            try:body=parse_body(data,action)
            except (ValueError,RecursionError):raise refused(400,'Invalid group wrap request') from None
            async with capacity(request.app.state.group_wrap_tenant_slots[tenant]), capacity(request.app.state.group_wrap_slots):
                result=await connected(request,action,binding,body)
            return JSONResponse(result,headers=PRIVATE)
    except HistoryConflict:raise refused(409,'Group wrap authority changed; reconcile') from None
    except (AdmissionRejected,GroupWrapRejected):raise refused(403,'Group wrap refused') from None
    except TimeoutError:raise refused(503,'Group wraps unavailable') from None


@router.post('/wrap-view')
async def view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('wrap-view',request,tenant,user)


@router.post('/item-view')
async def item_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-view',request,tenant,user)


@router.post('/item-authority-view')
async def item_authority_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-authority-view',request,tenant,user)


@router.post('/wrap-publish')
async def publish(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('wrap-publish',request,tenant,user)


@router.post('/wrap-read')
async def read(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('wrap-read',request,tenant,user)


@router.post('/item-grant-view')
async def item_grant_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-grant-view',request,tenant,user)


@router.post('/item-grant-append')
async def item_grant_append(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-grant-append',request,tenant,user)


@router.post('/item-grant-state')
async def item_grant_state(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-grant-state',request,tenant,user)


@router.post('/item-epoch-view')
async def item_epoch_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-epoch-view',request,tenant,user)


@owner_router.post('/item-epoch-append')
async def item_epoch_append(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-epoch-append',request,tenant,user)


@owner_router.post('/item-epoch-state')
async def item_epoch_state(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-epoch-state',request,tenant,user)


@owner_router.post('/item-status-view')
async def item_status_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-status-view',request,tenant,user)


@owner_router.post('/item-status-append')
async def item_status_append(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-status-append',request,tenant,user)


@owner_router.post('/item-status-state')
async def item_status_state(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-status-state',request,tenant,user)


@owner_router.post('/item-wrap-view')
async def item_wrap_view(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('item-wrap-view',request,tenant,user)
