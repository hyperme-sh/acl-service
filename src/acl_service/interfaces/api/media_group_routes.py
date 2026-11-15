"""Bounded group commands using existing fixed private-media identity bindings."""
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

router = APIRouter(prefix='/acl/sociacl/media/groups', tags=['SociACL'])
FIELDS = {
    'catalog': {'page'},
    'key-view': {'predicate','set'},
    'key-append': {'predicate','set','at','fence','command'},
    'key-state': {'predicate','set','command'},
    'create-view': {'object','predicate','set'},
    'create': {'object','predicate','set','at','fence','config'},
    'create-state': {'object','predicate','set','config'},
    'member-view': {'predicate','set','member','role','stated'},
    'member-append': {'predicate','set','member','role','at','fence','row'},
    'member-state': {'predicate','set','member','role','row'},
}


def _body(action, raw):
    body = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    if type(body) is not dict or set(body) != FIELDS[action]: raise ValueError()
    if action == 'catalog':
        if type(body['page']) is not int or not 0 <= body['page'] < 16: raise ValueError()
        return body
    if body['predicate'] not in ('same-group','named-circle'): raise ValueError()
    if type(body['set']) is not str or re.fullmatch(r'set_[\x21-\x7e]{1,508}',body['set']) is None: raise ValueError()
    for name in ('object','member'):
        if name in body and (type(body[name]) is not str or re.fullmatch(r'[\x21-\x7e]{1,512}',body[name]) is None): raise ValueError()
    if 'role' in body and body['role'] not in ('member','set'): raise ValueError()
    if 'stated' in body and (type(body['stated']) is not int or body['stated'] not in (0,1)): raise ValueError()
    if 'at' in body and (type(body['at']) is not int or not 0<=body['at']<=9007199254740991): raise ValueError()
    if 'fence' in body and (type(body['fence']) is not str or re.fullmatch(r'[a-f0-9]{64}',body['fence']) is None): raise ValueError()
    for name in ('config','row','command'):
        if name in body and type(body[name]) is not dict: raise ValueError()
    return body


@router.post('/{action}')
async def group_operation(action: str, request: Request,
                          tenant: UUID = Depends(require_matched_tenant),
                          user: AuthMeResponse = Depends(get_current_user)):
    if action not in FIELDS: raise refused(404,'Unknown group operation')
    bindings = request.app.state.private_wrap_bindings
    if bindings is None: raise refused(503,'Group source unavailable')
    binding = bindings.get((tenant,user.sub))
    if (binding is None or binding.tenant != str(tenant) or binding.store.tenant != str(tenant)
            or not {'acl:media:read','acl:media:write'}.issubset(user.scopes)):
        raise refused(403,'Group access refused')
    method = getattr(binding.authority,'group_operation',None)
    if not callable(method): raise refused(503,'Group source unavailable')
    if not request.app.state.rate_limiter.allow(tenant,user.sub): raise refused(429,'Rate limit exceeded')
    try:
        async with asyncio.timeout(4):
            if request.headers.get('content-type','').split(';')[0] != 'application/json' or request.headers.get('content-encoding','identity') != 'identity':
                raise refused(415,'Expected uncompressed JSON')
            raw = bytearray()
            async with capacity(request.app.state.private_wrap_body_slots[(tenant,user.sub)]):
                async with asyncio.timeout(1):
                    async for chunk in request.stream():
                        if len(raw)+len(chunk)>(73728 if action in ('key-append','key-state') else 18432): raise refused(413,'Request too large')
                        raw.extend(chunk)
            try: body = _body(action,raw)
            except (ValueError,TypeError,RecursionError): raise refused(400,'Invalid group request') from None
            async with capacity(request.app.state.private_wrap_slots):
                async with capacity(request.app.state.private_wrap_tenant_slots[tenant]):
                    result = await method(action,str(tenant),binding.reader,body)
            return JSONResponse(result,headers=PRIVATE)
    except HistoryConflict: raise refused(409,'Group source changed') from None
    except AdmissionRejected: raise refused(403,'Group access refused') from None
    except (TimeoutError,ValueError): raise refused(503,'Group source unavailable') from None
