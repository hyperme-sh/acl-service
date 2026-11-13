"""Bounded owner writes to an existing protected media source; no provisioning."""
import asyncio
import json
import re
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, capacity, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix='/acl/sociacl/media/owner', tags=['SociACL'])


@router.post('/{action}')
async def owner_operation(action: str, request: Request,
                          tenant: UUID = Depends(require_matched_tenant),
                          user: AuthMeResponse = Depends(get_current_user)):
    if action not in ('view', 'mutate'):
        raise refused(404, 'Unknown media operation')
    bindings = request.app.state.private_wrap_bindings
    if bindings is None:
        raise refused(503, 'Private media source unavailable')
    binding = bindings.get((tenant, user.sub))
    if (binding is None or binding.tenant != str(tenant)
            or binding.store.tenant != str(tenant) or 'acl:media:write' not in user.scopes):
        raise refused(403, 'Private media access refused')
    if not request.app.state.rate_limiter.allow(tenant, user.sub):
        raise refused(429, 'Rate limit exceeded')
    try:
        async with asyncio.timeout(4.0):
            if (request.headers.get('content-type', '').split(';')[0] != 'application/json'
                    or request.headers.get('content-encoding', 'identity') != 'identity'):
                raise refused(415, 'Expected uncompressed JSON')
            data = bytearray()
            async with capacity(request.app.state.private_wrap_body_slots[(tenant, user.sub)]):
                async with asyncio.timeout(1.0):
                    async for chunk in request.stream():
                        if len(data) + len(chunk) > (2048 if action == 'view' else 81920):
                            raise refused(413, 'Request too large')
                        data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields,
                                  parse_constant=_invalid_constant)
                expected = {'object'} if action == 'view' else {'object', 'at', 'fence', 'operation', 'payload'}
                if (type(body) is not dict or set(body) != expected or type(body['object']) is not str
                        or re.fullmatch(r'[\x21-\x7e]{1,512}', body['object']) is None):
                    raise ValueError()
                if action == 'mutate' and (
                        type(body['at']) is not int or not 0 <= body['at'] <= 9007199254740991
                        or type(body['fence']) is not str or re.fullmatch(r'[0-9a-f]{64}', body['fence']) is None
                        or type(body['operation']) is not str or body['operation'] not in ('grant', 'epoch', 'status', 'wrap')
                        or type(body['payload']) is not dict):
                    raise ValueError()
            except (ValueError, RecursionError):
                raise refused(400, 'Invalid media request') from None
            async with capacity(request.app.state.private_wrap_tenant_slots[tenant]):
                async with capacity(request.app.state.private_wrap_slots):
                    if action == 'view':
                        result = await binding.authority.owner_view(str(tenant), binding.reader, body['object'])
                    else:
                        accepted = await binding.authority.owner_mutate(
                            str(tenant), binding.reader, body['object'], body['at'], body['fence'],
                            body['operation'], body['payload'])
                        if accepted is not True:
                            raise AdmissionRejected('media write refused')
                        result = {'accepted': True}
            return JSONResponse(result, headers=PRIVATE)
    except HistoryConflict:
        raise refused(409, 'Private media source changed') from None
    except AdmissionRejected:
        raise refused(403, 'Private media access refused') from None
    except TimeoutError:
        raise refused(503, 'Private media source unavailable') from None
