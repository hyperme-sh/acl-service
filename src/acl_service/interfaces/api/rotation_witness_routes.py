"""Subject-bound wallet rotation; missing protected configuration refuses."""
import asyncio
import json
import hashlib
import re
import threading
import subprocess
from uuid import UUID
from dataclasses import dataclass
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.contact_routes import connected_result
from acl_service.interfaces.api.private_wrap_routes import PRIVATE, refused
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant
from acl_service.nightly import check_scope

router = APIRouter(prefix='/acl/sociacl/rotation', tags=['SociACL'])


@dataclass(frozen=True)
class RotationBinding:
    principal: str
    source: object


@router.post('/wallet')
async def wallet_rotation(request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    return await _rotation(request,tenant,user,'attest')


@router.post('/wallet/publish')
async def publish_rotation(request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    return await _rotation(request,tenant,user,'publish')


@router.post('/wallet/state')
async def rotation_state(request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    return await _rotation(request,tenant,user,'state')


async def _rotation(request, tenant, user, action):
    check_scope(tenant, user.sub)
    if 'acl:identity:rotate' not in user.scopes: raise refused(403, 'Rotation refused')
    if action != 'attest' and not getattr(request.app.state, 'rotation_publication_enabled', False):
        raise refused(503, 'Rotation publication unavailable')
    bindings = getattr(request.app.state, 'rotation_witness_bindings', None)
    if bindings is None: raise refused(503, 'Rotation unavailable')
    binding = bindings.get((tenant, user.sub))
    if binding is None: raise refused(403, 'Rotation refused')
    if not request.app.state.rate_limiter.allow(tenant, user.sub): raise refused(429, 'Rotation rate exceeded')
    slots = request.app.state.rotation_witness_slots
    if slots.locked(): raise refused(429, 'Rotation busy')
    await slots.acquire()
    stopped, work = threading.Event(), None
    def guard():
        if stopped.is_set(): raise HistoryConflict('rotation request expired')
        check_scope(tenant, user.sub)
    try:
        async with asyncio.timeout(12):
            if (request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json'
                    or request.headers.get('content-encoding','identity') != 'identity'):
                raise refused(415, 'Expected uncompressed JSON')
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > 256 * 1024: raise refused(413, 'Rotation request too large')
                data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
                if action == 'state':
                    if type(body) is not dict or set(body) != {'record'}:raise ValueError()
                    body=body['record']
                fields = {'v','kind','principal','seq','prevKey','nextKey','nextEpub','issuedAt','retainedLinks','authorizer','nextSig'}
                if action != 'attest':fields.add('attest')
                if type(body) is not dict or set(body) != fields or body.get('kind') != 'rotate':raise ValueError()
                authorizer = body['authorizer']
                if type(authorizer) is not dict or set(authorizer) != {'kind','link','siwe'} or authorizer['kind'] != 'wallet':raise ValueError()
                proof = authorizer['siwe']
                if type(proof) is not dict or set(proof) != {'message','signature'}:raise ValueError()
                json.dumps(body, allow_nan=False)
            except (ValueError, TypeError, RecursionError): raise refused(400, 'Invalid rotation request') from None
            if body['principal'] != binding.principal:
                raise refused(403, 'Rotation refused')
            method = {'attest':'attest_wallet_rotation','publish':'publish_wallet_rotation','state':'wallet_rotation_state'}[action]
            digest = hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
            payload = digest if action == 'state' else body
            work = asyncio.create_task(asyncio.to_thread(getattr(binding.source,method), binding.principal, payload, cancel=guard))
            result = await connected_result(request, work, stopped)
            if action == 'attest':
                if not isinstance(result, str) or not 0 < len(result) <= 16384:raise ValueError()
                result = {'attest':result}
            else:
                keys = {'recordHash','present','head'} if action == 'state' else {'recordHash'}
                if type(result) is not dict or set(result) != keys or result['recordHash'] != digest:raise ValueError()
                if action == 'state':
                    head = result['head']
                    if (type(result['present']) is not bool or type(head) is not dict or
                            set(head) != {'sequence','currentKey','currentEpub'} or type(head['sequence']) is not int or
                            not 0 <= head['sequence'] <= 9007199254740991 or
                            any(not isinstance(head[key],str) or re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}',head[key]) is None for key in ('currentKey','currentEpub'))):raise ValueError()
            return JSONResponse(result, headers=PRIVATE)
    except AdmissionRejected: raise refused(403, 'Rotation refused') from None
    except HistoryConflict: raise refused(409, 'Rotation changed') from None
    except (TimeoutError, OSError, RuntimeError, ValueError, subprocess.SubprocessError): raise refused(503, 'Rotation unavailable') from None
    finally:
        stopped.set()
        if work is not None and not work.done():
            def finished(task):
                if not task.cancelled(): task.exception()
                slots.release()
            work.add_done_callback(finished)
        else: slots.release()
