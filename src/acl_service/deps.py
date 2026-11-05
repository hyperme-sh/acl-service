from __future__ import annotations

import asyncio
import uuid

from fastapi import Depends, HTTPException, Request, status

from controlplane_api.exceptions import ForbiddenException
from auth_service.deps import get_current_tenant as get_current_tenant_from_token
from auth_service.deps import get_current_user
from auth_service.schemas import AuthMeResponse

MatchedTenantId = uuid.UUID


async def require_matched_tenant(
    request: Request,
    tenant: uuid.UUID = Depends(get_current_tenant_from_token),
) -> MatchedTenantId:
    raw = request.headers.get("X-Tenant-ID")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID header is required",
        )
    try:
        hdr = uuid.UUID(str(raw))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Tenant-ID",
        ) from e
    if hdr != tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="X-Tenant-ID must match tenant in access token",
        )
    return tenant


def require_permission(resource: str, action: str):
    async def _dep(
        request: Request,
        tenant_id: MatchedTenantId = Depends(require_matched_tenant),
        me: AuthMeResponse = Depends(get_current_user),
    ) -> None:
        from acl_service.infrastructure.enforcer_factory import enforce_rbac

        eng = request.app.state.policy_store
        sub = f"user:{me.sub}"
        ok = await asyncio.to_thread(
            enforce_rbac, eng, tenant_id, sub, resource, action
        )
        if not ok:
            raise ForbiddenException("Permission denied for this resource")

    return _dep


__all__ = [
    "get_current_tenant_from_token",
    "get_current_user",
    "require_matched_tenant",
    "require_permission",
]


async def optional_authenticated_user(request: Request) -> AuthMeResponse | None:
    """Keep public shares anonymous; verify any supplied bearer credential."""
    if not request.headers.get("Authorization"):
        return None
    from auth_service.deps import http_bearer, bearer_access_token, get_access_token_claims
    credentials = await http_bearer(request)
    token = await bearer_access_token(credentials)
    return AuthMeResponse.from_claims(await get_access_token_claims(token))
