"""Subject-bound allocation; browser input cannot select issuer, source or policy."""
import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, capacity, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router=APIRouter(prefix='/acl/sociacl/media',tags=['SociACL'])


async def connected_allocate(request, binding, record):
    async def disconnected():
        while not await request.is_disconnected():
            await asyncio.sleep(0.05)
    work=asyncio.create_task(binding.allocate(record))
    monitor=asyncio.create_task(disconnected())
    try:
        done,_=await asyncio.wait((work,monitor),return_when=asyncio.FIRST_COMPLETED)
        if monitor in done:raise TimeoutError('Allocation requester disconnected')
        return await work
    finally:
        work.cancel();monitor.cancel()
        await asyncio.gather(work,monitor,return_exceptions=True)


@router.post('/allocate')
async def allocate(request: Request, tenant: UUID=Depends(require_matched_tenant),
                   user: AuthMeResponse=Depends(get_current_user)):
    bindings=request.app.state.media_allocation_bindings
    if bindings is None:raise refused(503,'Media allocation unavailable')
    binding=bindings.get((tenant,user.sub))
    if (binding is None or binding.tenant!=str(tenant) or binding.client.tenant!=str(tenant)
            or 'acl:media:write' not in user.scopes):
        raise refused(403,'Media allocation refused')
    if not request.app.state.rate_limiter.allow(tenant,user.sub):raise refused(429,'Rate limit exceeded')
    if (request.headers.get('content-type','').split(';')[0]!='application/json'
            or request.headers.get('content-encoding','identity')!='identity'):
        raise refused(415,'Expected uncompressed JSON')
    try:
        async with asyncio.timeout(5), capacity(request.app.state.media_allocation_body_slots[(tenant,user.sub)]):
            data=bytearray()
            async with asyncio.timeout(1):
                async for chunk in request.stream():
                    if len(data)+len(chunk)>2048:raise refused(413,'Request too large')
                    data.extend(chunk)
            try:
                record=json.loads(data,object_pairs_hook=_unique_fields,parse_constant=_invalid_constant)
                if type(record) is not dict or set(record)!={'object','owner','issuedAt','sig'}:raise ValueError()
            except (ValueError,RecursionError):raise refused(400,'Invalid ownership record') from None
            async with capacity(request.app.state.media_allocation_tenant_slots[tenant]), capacity(request.app.state.media_allocation_slots):
                result=await connected_allocate(request,binding,record)
            return JSONResponse(result,headers=PRIVATE)
    except HistoryConflict:raise refused(409,'Media allocation changed; reconcile') from None
    except AdmissionRejected:raise refused(403,'Media allocation refused') from None
    except TimeoutError:raise refused(503,'Media allocation unavailable') from None
