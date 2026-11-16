"""Owner admission around native device-transfer reads and their worker guards."""
import json
import os
from fastapi import Depends, HTTPException
from jwt import InvalidTokenError
from auth_service.deps import bearer_access_token, get_access_token_claims
from controlplane_identity.nightly import current_binding, require_original_run, require
from controlplane_identity.nightly_http import Authority, RunMiddleware

PATH = '/api/v1/acl/sociacl/device-transfer/'
CONTROL = '/api/v1/acl/internal/nightly-run'


async def verified_claims(token=Depends(bearer_access_token)):
    claims = await get_access_token_claims(token)
    try:
        require_original_run(claims)
    except (ValueError, InvalidTokenError):
        raise HTTPException(403, 'Transfer authority refused') from None
    return claims


def install(app):
    # Cover native Auth introspection as well as shared JWT verification.
    app.dependency_overrides[get_access_token_claims] = verified_claims
    raw = os.environ.get('ACL_NIGHTLY_RUN_CONFIG')
    if raw is None:
        return
    require(len(raw.encode()) <= 65536)
    authority = Authority(json.loads(raw), 'acl')
    app.add_middleware(RunMiddleware, authority=authority,
        paths={('POST', PATH + action) for action in ('state', 'current')}, control_path=CONTROL)


def check_scope(tenant, subject, scope=None):
    binding = current_binding()
    if binding is None:
        return
    admitted = binding['scope']
    require(str(tenant) == admitted['tenant'] and subject == admitted['subject'])
    if scope is not None:
        require(scope['tenant'] == admitted['tenant'])
        require(all(scope[key] in admitted['origins'] for key in ('sourceOrigin', 'destinationOrigin')))
