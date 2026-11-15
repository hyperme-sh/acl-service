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


async def execute(action,binding,body):
    args=(binding.tenant,binding.reader,body['predicate'],body['set'])
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
    expected={'predicate','set'}
    if action=='item-view':expected.add('object')
    if action=='wrap-publish':expected|={'at','fence','metadata','payload'}
    if (type(body) is not dict or set(body)!=expected or body['predicate'] not in ('same-group','named-circle')
            or type(body['set']) is not str or re.fullmatch(r'set_p_[0-9a-f]{128}_[0-9a-f]{32}',body['set']) is None):raise ValueError()
    if action=='item-view' and (type(body['object']) is not str
            or re.fullmatch(r'[\x21-\x7e]{1,512}',body['object']) is None):raise ValueError()
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
            data=bytearray();limit=92160 if action=='wrap-publish' else 2048
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


@router.post('/wrap-publish')
async def publish(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('wrap-publish',request,tenant,user)


@router.post('/wrap-read')
async def read(request:Request,tenant:UUID=Depends(require_matched_tenant),user:AuthMeResponse=Depends(get_current_user)):
    return await operation('wrap-read',request,tenant,user)
