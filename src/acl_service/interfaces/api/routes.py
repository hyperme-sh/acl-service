from __future__ import annotations

import asyncio
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from controlplane_api.event_types import ACL_POLICY_UPDATED_V1
from acl_service.infrastructure.atomic import atomic_store
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
from acl_service.domain.policy_store import add_rule, delete_rule, list_rules

router = APIRouter(tags=["ACL"])


def _emit_policy_updated(tx, tenant_id, operation, ptype, me, preview, row_id):
    tx.emit(tenant_id=tenant_id,event_type=ACL_POLICY_UPDATED_V1,
        operation_id=f'{row_id}:{operation}:{me.sub}',
        payload=AclPolicyUpdatedPayload(tenant_id=tenant_id,operation=operation,
            ptype=ptype,actor_sub=str(me.sub),rule_preview=preview).to_envelope_payload())


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
    eng = request.app.state.policy_store

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
    eng = request.app.state.policy_store
    def _run():
        with atomic_store(eng) as tx:
            tx.lock(f'policy:{tenant_id}:{body.ptype}:{body.rule}')
            row = add_rule(tx.store,tenant_id,body.ptype,body.rule)
            preview = ','.join([body.ptype,*body.rule])[:512]
            _emit_policy_updated(tx,tenant_id,'added',body.ptype,me,preview,row.id)
            return PolicyRowResponse(id=row.id,ptype=row.ptype,**{f'v{i}':getattr(row,f'v{i}') for i in range(6)})
    return await asyncio.to_thread(_run)


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
    eng = request.app.state.policy_store
    def _run():
        with atomic_store(eng) as tx:
            tx.lock(f'policy:{tenant_id}:{body.ptype}:{body.rule}')
            candidates=[r for r in list_rules(tx.store,tenant_id) if r.ptype==body.ptype and [getattr(r,f'v{i}') for i in range(6)]==body.rule+[None]*(6-len(body.rule))]
            if not candidates or not delete_rule(tx.store,tenant_id,body.ptype,body.rule):
                raise HTTPException(status_code=404,detail='Policy rule not found')
            preview=','.join([body.ptype,*body.rule])[:512]
            _emit_policy_updated(tx,tenant_id,'removed',body.ptype,me,preview,min(r.id for r in candidates))
            return Response(status_code=status.HTTP_204_NO_CONTENT)
    return await asyncio.to_thread(_run)


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
    eng = request.app.state.policy_store
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
