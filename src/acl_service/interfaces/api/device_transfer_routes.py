"""Read-only, subject-bound transfer authority. Never accepts secret key bytes."""
import asyncio
import json
import threading
import subprocess
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.device_transfer import request_value
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.contact_routes import connected_result
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix='/acl/sociacl/device-transfer', tags=['SociACL'])


@router.post('/{action}')
async def device_transfer(action: str, request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    if action not in ('state','current'): raise refused(404, 'Unknown transfer operation')
    if 'acl:identity:transfer' not in user.scopes: raise refused(403, 'Transfer refused')
    bindings = request.app.state.device_transfer_bindings
    if bindings is None: raise refused(503, 'Transfer unavailable')
    binding = bindings.get((tenant, user.sub))
    if binding is None: raise refused(403, 'Transfer refused')
    if not request.app.state.rate_limiter.allow(tenant, user.sub): raise refused(429, 'Transfer rate exceeded')
    slots = request.app.state.device_transfer_slots
    if slots.locked(): raise refused(429, 'Transfer busy')
    await slots.acquire()
    stopped, work = threading.Event(), None
    def guard():
        if stopped.is_set(): raise HistoryConflict('transfer request expired')
    try:
        async with asyncio.timeout(12):
            if (request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json'
                    or request.headers.get('content-encoding','identity') != 'identity'):
                raise refused(415, 'Expected uncompressed JSON')
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > 4096: raise refused(413, 'Transfer request too large')
                data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
                scope, identity, transfer, revision = request_value(action, body)
            except (ValueError, TypeError, RecursionError): raise refused(400, 'Invalid transfer request') from None
            if scope['tenant'] != str(tenant) or identity['principal'] != binding.principal:
                raise refused(403, 'Transfer refused')
            work = asyncio.create_task(asyncio.to_thread(binding.source.read, binding.principal, scope, identity, transfer, revision, guard))
            result = await connected_result(request, work, stopped)
            return JSONResponse(result, headers=PRIVATE)
    except AdmissionRejected: raise refused(403, 'Transfer refused') from None
    except HistoryConflict: raise refused(409, 'Transfer changed') from None
    except (TimeoutError, OSError, RuntimeError, ValueError, subprocess.SubprocessError): raise refused(503, 'Transfer unavailable') from None
    finally:
        stopped.set()
        if work is not None and not work.done():
            def finished(task):
                if not task.cancelled(): task.exception()
                slots.release()
            work.add_done_callback(finished)
        else: slots.release()
