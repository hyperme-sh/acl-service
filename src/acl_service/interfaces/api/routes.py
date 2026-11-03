from __future__ import annotations

import asyncio
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from controlplane_api.event_types import ACL_POLICY_UPDATED_V1
from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
from auth_service.schemas import AuthMeResponse
from controlplane_events.payloads import AclPolicyUpdatedPayload

from acl_service.deps import get_current_user, require_matched_tenant, require_permission
from acl_service.domain.dtos import (
    EnforceRequest,
    EnforceResponse,
    PolicyRowResponse,
    PolicyRuleCreate,
    PolicyRuleDelete,
)
from acl_service.infrastructure.enforcer_factory import make_enforcer
from acl_service.infrastructure.policy_repo import add_rule, delete_rule, list_rules

router = APIRouter(tags=["ACL"])


async def _emit_policy_updated(
    tenant_id: uuid.UUID,
    operation: Literal["added", "removed", "replaced"],
    ptype: str,
    me: AuthMeResponse,
    preview: str | None,
) -> None:
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=ACL_POLICY_UPDATED_V1,
        payload=AclPolicyUpdatedPayload(
            tenant_id=tenant_id,
            operation=operation,  # type: ignore[arg-type]
            ptype=ptype,
            actor_sub=str(me.sub),
            rule_preview=preview,
        ).to_envelope_payload(),
    )


@router.get(
    "/acl/policies",
    response_model=list[PolicyRowResponse],
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_policies(
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    _me: AuthMeResponse = Depends(get_current_user),
):
    eng = request.app.state.sync_engine

    def _run():
        return list_rules(eng, tenant_id)

    rows = await asyncio.to_thread(_run)
    return [
        PolicyRowResponse(
            id=r.id,
            ptype=r.ptype,
            v0=r.v0,
            v1=r.v1,
            v2=r.v2,
            v3=r.v3,
            v4=r.v4,
            v5=r.v5,
        )
        for r in rows
    ]


@router.post(
    "/acl/policies",
    response_model=PolicyRowResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def create_policy(
    body: PolicyRuleCreate,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    _management: None = Depends(require_permission("/acl/policies", "manage")),
):
    eng = request.app.state.sync_engine

    def _run():
        return add_rule(eng, tenant_id, body.ptype, body.rule)

    row = await asyncio.to_thread(_run)
    preview = ",".join([body.ptype, *body.rule])[:512]
    await _emit_policy_updated(tenant_id, "added", body.ptype, me, preview)
    return PolicyRowResponse(
        id=row.id,
        ptype=row.ptype,
        v0=row.v0,
        v1=row.v1,
        v2=row.v2,
        v3=row.v3,
        v4=row.v4,
        v5=row.v5,
    )


@router.delete(
    "/acl/policies",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def remove_policy(
    body: PolicyRuleDelete,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    _management: None = Depends(require_permission("/acl/policies", "manage")),
):
    eng = request.app.state.sync_engine

    def _run():
        return delete_rule(eng, tenant_id, body.ptype, body.rule)

    ok = await asyncio.to_thread(_run)
    if not ok:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Policy rule not found")
    preview = ",".join([body.ptype, *body.rule])[:512]
    await _emit_policy_updated(tenant_id, "removed", body.ptype, me, preview)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/acl/enforce",
    response_model=EnforceResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def enforce_check(
    body: EnforceRequest,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
):
    lim = getattr(request.app.state, "rate_limiter", None)
    if lim is not None and not lim.allow(tenant_id, str(me.sub)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="ACL enforce rate limit exceeded for this tenant and user",
        )
    eng = request.app.state.sync_engine
    model_file = "model_rbac.conf" if body.model == "rbac" else "model_abac.conf"

    def _run():
        e = make_enforcer(eng, tenant_id, model_file=model_file)
        if body.model == "rbac":
            return bool(e.enforce(body.sub, body.obj, body.act))
        if body.extra is None:
            return False
        return bool(e.enforce(body.sub, body.obj, body.act, body.extra))

    allow = await asyncio.to_thread(_run)
    return EnforceResponse(allow=allow)


@router.get(
    "/acl/protected-ping",
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def protected_ping(
    _: None = Depends(require_permission("/acl/protected-ping", "read")),
):
    return {"ok": True}
