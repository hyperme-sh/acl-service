"""Bounded owner writes to an existing protected media source; no provisioning."""
import asyncio
import base64
import binascii
import json
import re
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.domain.private_wrap_publication import publish_private_wrap, WrapPublicationRejected
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, capacity, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix='/acl/sociacl/media/owner', tags=['SociACL'])


@router.post('/{action}')
async def owner_operation(action: str, request: Request,
                          tenant: UUID = Depends(require_matched_tenant),
                          user: AuthMeResponse = Depends(get_current_user)):
    if action not in ('catalog', 'cleanup-catalog', 'view', 'group-view', 'group-authority-view', 'group-check', 'group-policy-view', 'epoch-view', 'status-view', 'share-view', 'unshare-view', 'cancel-view', 'mutate', 'group-append', 'group-policy-append', 'publish-wrap', 'upload-state', 'share-state', 'share-check', 'delete-view', 'delete', 'cleanup', 'registration'):
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
                        limit = 18432 if action == 'group-policy-append' else 4096 if action == 'registration' else 81920 if action == 'group-check' else 2048 if action in ('catalog', 'cleanup-catalog', 'view', 'group-view', 'group-authority-view', 'group-check', 'group-policy-view', 'epoch-view', 'status-view', 'share-view', 'unshare-view', 'cancel-view', 'delete-view', 'cleanup') else 12288 if action == 'delete' else 100000 if action == 'publish-wrap' else 81920
                        if len(data) + len(chunk) > limit:
                            raise refused(413, 'Request too large')
                        data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields,
                                  parse_constant=_invalid_constant)
                expected = {'object'} if action in ('view', 'group-view', 'group-authority-view', 'group-check', 'group-policy-view', 'epoch-view', 'delete-view', 'cleanup') else {'object', 'at', 'fence', 'operation', 'payload'}
                if action == 'group-policy-view': expected = {'object','predicate','set'}
                if action == 'group-policy-append': expected = {'object','at','fence','predicate','set','config'}
                if action == 'registration': expected = {'object','record'}
                if action == 'group-check': expected = {'object','predicate','set','rows'}
                if action == 'group-append': expected = {'object','at','fence','predicate','set','rows'}
                if action == 'delete': expected = {'object', 'at', 'proof'}
                if action in ('catalog', 'cleanup-catalog'): expected = {'page'}
                if action in ('upload-state', 'share-state', 'share-check'): expected = {'object', 'operation', 'payload'}
                if action in ('status-view', 'share-view', 'unshare-view', 'cancel-view'): expected = {'object', 'reader'}
                if action == 'publish-wrap': expected = {'object', 'at', 'fence', 'metadata', 'wrapBase64'}
                if type(body) is not dict or set(body) != expected:
                    raise ValueError()
                if action in ('catalog', 'cleanup-catalog'):
                    if type(body['page']) is not int or not 0 <= body['page'] < 16:
                        raise ValueError()
                elif (type(body['object']) is not str or re.fullmatch(r'[\x21-\x7e]{1,512}', body['object']) is None):
                    raise ValueError()
                if action in ('status-view', 'share-view', 'unshare-view', 'cancel-view') and (type(body['reader']) is not str
                        or re.fullmatch(r'[\x21-\x7e]{1,512}', body['reader']) is None):
                    raise ValueError()
                if action not in ('catalog', 'cleanup-catalog', 'view', 'group-view', 'group-authority-view', 'group-check', 'group-policy-view', 'epoch-view', 'status-view', 'share-view', 'unshare-view', 'cancel-view', 'upload-state', 'share-state', 'share-check', 'delete-view', 'delete', 'cleanup', 'registration') and (
                        type(body['at']) is not int or not 0 <= body['at'] <= 9007199254740991
                        or type(body['fence']) is not str or re.fullmatch(r'[0-9a-f]{64}', body['fence']) is None):
                    raise ValueError()
                if action in ('group-append','group-check','group-policy-view','group-policy-append') and (
                        body['predicate'] not in ('same-group','named-circle') or type(body['set']) is not str
                        or re.fullmatch(r'set_[\x21-\x7e]{1,508}',body['set']) is None):
                    raise ValueError()
                if action == 'group-policy-append' and type(body['config']) is not dict:raise ValueError()
                if action in ('group-append','group-check') and (type(body['rows']) is not list or not 1<=len(body['rows'])<=64):
                    raise ValueError()
                if action == 'registration' and type(body['record']) is not dict: raise ValueError()
                if action == 'delete' and (type(body['at']) is not int or not 0<=body['at']<=9007199254740991 or type(body['proof']) is not dict):
                    raise ValueError()
                if action == 'mutate' and (type(body['operation']) is not str
                        or body['operation'] not in ('grant', 'epoch', 'status', 'wrap') or type(body['payload']) is not dict):
                    raise ValueError()
                if action in ('upload-state', 'share-state', 'share-check') and (body['operation'] not in ('grant', 'epoch', 'wrap') or type(body['payload']) is not dict):
                    raise ValueError()
                if action == 'publish-wrap':
                    if type(body['metadata']) is not dict or type(body['wrapBase64']) is not str:
                        raise ValueError()
                    payload = base64.b64decode(body['wrapBase64'], validate=True)
                    if not 0 < len(payload) <= 65536 or base64.b64encode(payload).decode('ascii') != body['wrapBase64']:
                        raise ValueError()
            except (ValueError, RecursionError, binascii.Error):
                raise refused(400, 'Invalid media request') from None
            async with capacity(request.app.state.private_wrap_tenant_slots[tenant]):
                async with capacity(request.app.state.private_wrap_slots):
                    if action in ('catalog', 'cleanup-catalog'):
                        catalog = binding.authority.owner_cleanup_catalog if action=='cleanup-catalog' else binding.authority.owner_catalog
                        result = await catalog(str(tenant),binding.reader,body['page'])
                    elif action == 'registration':
                        if await binding.authority.owner_confirm_registration(str(tenant),binding.reader,body['object'],body['record']) is not True:
                            raise AdmissionRejected('Media registration refused')
                        result={'accepted':True}
                    elif action in ('upload-state', 'share-state', 'share-check'):
                        method=getattr(binding.authority,{'share-state':'owner_share_state','share-check':'owner_share_check','upload-state':'owner_upload_state'}[action],None)
                        if not callable(method): raise refused(503,'Private media source unavailable')
                        result = await method(str(tenant), binding.reader, body['object'], body['operation'], body['payload'])
                    elif action == 'delete-view':
                        result = await binding.authority.owner_deletion_view(str(tenant),binding.reader,body['object'])
                    elif action == 'cleanup':
                        allocations=getattr(request.app.state,'media_allocation_bindings',None) or {}
                        allocated=allocations.get((tenant,user.sub))
                        if (allocated is None or allocated.tenant!=str(tenant) or allocated.reader!=binding.reader
                                or allocated.authority is not binding.authority):
                            raise AdmissionRejected('Private media cleanup binding unavailable')
                        result=await allocated.retire(body['object'])
                    elif action == 'delete':
                        command = await binding.authority.owner_delete(str(tenant),binding.reader,body['object'],body['at'],body['proof'])
                        if type(command) is not str or re.fullmatch(r'[0-9a-f]{64}',command) is None:
                            raise AdmissionRejected('media deletion refused')
                        result = {'accepted':True,'command':command,'cleanup':'pending'}
                    elif action == 'group-policy-view':
                        prepare=getattr(binding.authority,'owner_group_policy_view',None)
                        if not callable(prepare):raise refused(503,'Private media source unavailable')
                        result=await prepare(str(tenant),binding.reader,body['object'],body['predicate'],body['set'])
                    elif action == 'group-policy-append':
                        append=getattr(binding.authority,'owner_append_group_policy',None)
                        if not callable(append):raise refused(503,'Private media source unavailable')
                        accepted=await append(str(tenant),binding.reader,body['object'],body['at'],body['fence'],
                                              body['predicate'],body['set'],body['config'])
                        if accepted is not True:raise AdmissionRejected('Group policy refused')
                        result={'accepted':True}
                    elif action == 'group-check':
                        check=getattr(binding.authority,'owner_group_append_state',None)
                        if not callable(check):raise refused(503,'Private media source unavailable')
                        result=await check(str(tenant),binding.reader,body['object'],body['predicate'],body['set'],body['rows'])
                    elif action == 'group-authority-view':
                        prepare=getattr(binding.authority,'owner_group_authority_view',None)
                        if not callable(prepare):raise refused(503,'Private media source unavailable')
                        result=await prepare(str(tenant),binding.reader,body['object'])
                    elif action == 'group-view':
                        prepare=getattr(binding.authority,'owner_group_view',None)
                        if not callable(prepare):raise refused(503,'Private media source unavailable')
                        result=await prepare(str(tenant),binding.reader,body['object'])
                    elif action == 'group-append':
                        append=getattr(binding.authority,'owner_append_group',None)
                        if not callable(append):raise refused(503,'Private media source unavailable')
                        accepted=await append(str(tenant),binding.reader,body['object'],body['at'],body['fence'],
                                              body['predicate'],body['set'],body['rows'])
                        if accepted is not True:raise AdmissionRejected('Group append refused')
                        result={'accepted':True}
                    elif action == 'view':
                        result = await binding.authority.owner_view(str(tenant), binding.reader, body['object'])
                    elif action == 'epoch-view':
                        prepare=getattr(binding.authority,'owner_epoch_view',None)
                        if not callable(prepare): raise refused(503,'Private media source unavailable')
                        result=await prepare(str(tenant),binding.reader,body['object'])
                    elif action in ('share-view','unshare-view'):
                        prepare=getattr(binding.authority,'owner_unshare_view' if action=='unshare-view' else 'owner_share_view',None)
                        if not callable(prepare): raise refused(503,'Private media source unavailable')
                        result=await prepare(str(tenant),binding.reader,body['object'],body['reader'])
                    elif action == 'status-view':
                        result = await binding.authority.owner_status_view(str(tenant),binding.reader,body['object'],body['reader'])
                    elif action == 'cancel-view':
                        result = await binding.authority.owner_cancel_view(str(tenant),binding.reader,body['object'],body['reader'])
                    elif action == 'publish-wrap':
                        digest = await publish_private_wrap(binding.authority, binding.store,
                            str(tenant), binding.reader, body['object'], body['at'], body['fence'], body['metadata'], payload)
                        result = {'record': digest, 'digest': digest}
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
    except WrapPublicationRejected:
        raise refused(403, 'Private media publication refused') from None
    except TimeoutError:
        raise refused(503, 'Private media source unavailable') from None
