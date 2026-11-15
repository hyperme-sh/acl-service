"""Tenant-bound contact document transport; callers never select a source."""
import asyncio
import base64
import json
import threading
from dataclasses import dataclass
from uuid import UUID

from auth_service.schemas import AuthMeResponse
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.contact_journal import LIMITS, PRINCIPAL
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix='/acl/sociacl/contacts', tags=['SociACL'])


@dataclass(frozen=True)
class ContactBinding:
    principal: str
    source: object


@router.post('/{operation}')
async def contact_operation(operation: str, request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    if operation not in ('read','write'):
        raise HTTPException(404,'Unknown contact operation')
    bindings = request.app.state.contact_bindings
    if bindings is None:
        raise HTTPException(503,'Contact source unavailable')
    binding = bindings.get((tenant,user.sub))
    if binding is None:
        raise HTTPException(403,'Contact source refused')
    if not request.app.state.rate_limiter.allow(tenant,user.sub):
        raise HTTPException(429,'Rate limit exceeded')
    slots = request.app.state.contact_slots
    if slots.locked():
        raise HTTPException(429,'Contact source busy')
    await slots.acquire()
    stopped, work = threading.Event(), None
    def guard():
        if stopped.is_set(): raise HistoryConflict('contact request expired')
    try:
        async with asyncio.timeout(1.5):
            if (request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json'
                    or request.headers.get('content-encoding','identity') != 'identity'):
                raise HTTPException(415,'Expected uncompressed JSON')
            data = bytearray()
            async for chunk in request.stream():
                if len(data)+len(chunk)>1400000: raise HTTPException(413,'Contact request too large')
                data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'),object_pairs_hook=_unique_fields,parse_constant=_invalid_constant)
                fields = {'owner','kind','evaluatedAt'} | ({'revision','payload','signature'} if operation=='write' else set())
                if (type(body) is not dict or set(body)!=fields or type(body['evaluatedAt']) is not int
                        or body['evaluatedAt']<0 or type(body['owner']) is not str
                        or PRINCIPAL.fullmatch(body['owner']) is None or type(body['kind']) is not str or body['kind'] not in LIMITS):
                    raise ValueError()
                if operation=='write':
                    if (type(body['revision']) is not int or not 0<=body['revision']<9007199254740991
                            or type(body['payload']) is not str or type(body['signature']) is not str or len(body['signature'])>128):
                        raise ValueError()
                    payload=base64.b64decode(body['payload'],validate=True)
                    low,high=LIMITS[body['kind']]
                    if base64.b64encode(payload).decode()!=body['payload'] or not low<=len(payload)<=high:raise ValueError()
            except (ValueError,TypeError,RecursionError) as exc:
                raise HTTPException(400,'Invalid contact request') from exc
            args=(str(tenant),binding.principal,body['owner'],body['kind'],body['evaluatedAt'])
            if operation=='read':
                work=asyncio.create_task(asyncio.to_thread(binding.source.read,*args,guard))
            else:
                work=asyncio.create_task(asyncio.to_thread(binding.source.write,*args,body['revision'],payload,body['signature'],guard))
            result=await asyncio.shield(work)
            return JSONResponse(result,headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})
    except AdmissionRejected as exc:raise HTTPException(403,'Contact source refused') from exc
    except HistoryConflict as exc:raise HTTPException(409,'Contact state changed') from exc
    except TimeoutError as exc:raise HTTPException(503,'Contact source timed out') from exc
    finally:
        stopped.set()
        if work is not None and not work.done():
            def finished(task):
                if not task.cancelled():task.exception()
                slots.release()
            work.add_done_callback(finished)
        else:slots.release()
