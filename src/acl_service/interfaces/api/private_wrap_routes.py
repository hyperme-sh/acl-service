"""Private wrap transport; no source, credentials or enrollment created here."""
import asyncio
import base64
from dataclasses import dataclass
import json
import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.private_wrap_delivery import (
    WrapAuthority, WrapDeliveryRejected, deliver_private_wrap_context,
)
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix='/acl/sociacl/media', tags=['SociACL'])
PRIVATE = {'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff'}


@dataclass(frozen=True)
class PrivateWrapBinding:
    tenant: str
    reader: str
    authority: WrapAuthority
    store: object


def refused(status, message):
    return HTTPException(status, message, headers=PRIVATE)


@router.post('/read-wrap')
async def read_wrap(request: Request, tenant: UUID = Depends(require_matched_tenant),
                    user: AuthMeResponse = Depends(get_current_user)):
    # The authenticated subject is mapped by the owner, never by request JSON.
    bindings = request.app.state.private_wrap_bindings
    if bindings is None:
        raise refused(503, 'Private wrap source unavailable')
    binding = bindings.get((tenant, user.sub))
    if binding is None or binding.tenant != str(tenant) or binding.store.tenant != str(tenant):
        raise refused(403, 'Private wrap access refused')
    if 'acl:media:read' not in user.scopes:
        raise refused(403, 'Private wrap access refused')
    if not request.app.state.rate_limiter.allow(tenant, user.sub):
        raise refused(429, 'Rate limit exceeded')
    slots = request.app.state.private_wrap_slots
    if slots.locked():
        raise refused(429, 'Private wrap source busy')
    await slots.acquire()
    try:
        async with asyncio.timeout(4.0):
            if (request.headers.get('content-type', '').split(';')[0] != 'application/json'
                    or request.headers.get('content-encoding', 'identity') != 'identity'):
                raise refused(415, 'Expected uncompressed JSON')
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > 2048:
                    raise refused(413, 'Request too large')
                data.extend(chunk)
            try:
                body = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields,
                                  parse_constant=_invalid_constant)
                if (type(body) is not dict or set(body) != {'object'}
                        or type(body['object']) is not str
                        or re.fullmatch(r'[\x21-\x7e]{1,512}', body['object']) is None):
                    raise ValueError()
            except (ValueError, RecursionError):
                raise refused(400, 'Invalid request') from None
            result = await deliver_private_wrap_context(binding.authority, binding.store,
                                                        str(tenant), binding.reader, body['object'])
            return JSONResponse({
                'context': {'object': result.object, 'epoch': result.epoch, 'revisionId': result.revision_id},
                'readerEpub': result.reader_epub, 'expiresAt': result.expires_at,
                'wrapBase64': base64.b64encode(result.payload).decode('ascii'),
            }, headers=PRIVATE)
    except WrapDeliveryRejected:
        raise refused(403, 'Private wrap access refused') from None
    except TimeoutError:
        raise refused(503, 'Private wrap source unavailable') from None
    finally:
        slots.release()
