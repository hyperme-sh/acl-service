from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.common.event_types import (
    SOCIACL_ACCESS_DECIDED_V1,
    SOCIACL_RECOVERY_SESSION_STARTED_V1,
    SOCIACL_SHARE_CREATED_V1,
    SOCIACL_SHARE_RESOLVED_V1,
)
from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
from auth_service.schemas import AuthMeResponse
from controlplane_events.payloads import (
    SociaclAccessDecidedPayload,
    SociaclRecoverySessionPayload,
    SociaclShareCreatedPayload,
    SociaclShareResolvedPayload,
)
from panopticon_models.sociacl import (
    RecoveryProofRequest,
    RecoverySessionCreate,
    RecoverySessionResponse,
    SociACLEvaluateRequest,
    SociACLShareLinkCreate,
    SociACLShareLinkPublic,
    SociACLDecisionKind,
    SociACLResourceKind,
    SociACLShareMode,
)

from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.dtos import SociaclShareCreatedResponse
from acl_service.domain.sociacl_evaluator import _share_active, evaluate_share_access
from acl_service.infrastructure.recovery_repo import create_or_get_session, transition_state
from acl_service.infrastructure.share_repo import (
    create_share,
    decrement_uses,
    hash_share_token,
    lookup_share_by_token_hash,
)

router = APIRouter(prefix="/acl/sociacl", tags=["SociACL"])


class _RateLimiter:
    def __init__(self, max_events: int = 60, window_sec: float = 60.0) -> None:
        self.max_events = max_events
        self.window_sec = window_sec
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > self.window_sec:
            q.popleft()
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True


_public_rl = _RateLimiter(120, 60.0)


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host or "unknown"
    return "unknown"


def _parse_expires_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    raw = s.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)


def _public_payload(link) -> SociACLShareLinkPublic:
    now = datetime.now(timezone.utc)
    active, _ = _share_active(link, now)
    exp = link.expires_at.isoformat() if link.expires_at else None
    return SociACLShareLinkPublic(
        share_id=link.id,
        mode=SociACLShareMode(link.mode),
        active=active,
        resource_kind=SociACLResourceKind(link.resource_kind),
        expires_at=exp,
        uses_remaining=link.uses_remaining,
    )


@router.post(
    "/shares",
    response_model=SociaclShareCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def sociacl_create_share(
    body: SociACLShareLinkCreate,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
):
    eng = request.app.state.sync_engine
    exp = _parse_expires_iso(body.expires_at)
    row, raw_token = create_share(
        eng,
        tenant_id=tenant_id,
        resource_kind=body.resource_kind.value,
        resource_descriptor=body.resource_descriptor,
        predicate_json=body.predicate.model_dump(mode="json"),
        mode=body.mode.value,
        expires_at=exp,
        uses_remaining=body.max_uses,
        owner_user_id=body.owner_user_id,
        group_id=body.group_id,
        created_by=str(me.sub),
    )
    pub = _public_payload(row)
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=SOCIACL_SHARE_CREATED_V1,
        payload=SociaclShareCreatedPayload(
            tenant_id=tenant_id,
            share_id=row.id,
            mode=body.mode.value,
            resource_kind=body.resource_kind.value,
            token_prefix=row.token_prefix,
            actor_sub=str(me.sub),
        ).to_envelope_payload(),
    )
    return SociaclShareCreatedResponse(
        share_id=row.id,
        token=raw_token,
        public=pub,
    )


@router.get(
    "/shares/by-token/{token}",
    response_model=SociACLShareLinkPublic,
)
async def sociacl_resolve_share(token: str, request: Request):
    ip = _client_ip(request)
    if not _public_rl.allow(f"resolve:{ip}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
    if len(token) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    eng = request.app.state.sync_engine
    th = hash_share_token(token)
    link = lookup_share_by_token_hash(eng, th)
    if link is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share not found")
    pub = _public_payload(link)
    await get_tenant_event_publisher().publish(
        tenant_id=link.tenant_id,
        event_type=SOCIACL_SHARE_RESOLVED_V1,
        payload=SociaclShareResolvedPayload(
            tenant_id=link.tenant_id,
            share_id=link.id,
            active=pub.active,
            actor_sub=None,
        ).to_envelope_payload(),
    )
    return pub


@router.post("/evaluate")
async def sociacl_evaluate(body: SociACLEvaluateRequest, request: Request):
    ip = _client_ip(request)
    if not _public_rl.allow(f"eval:{ip}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
    eng = request.app.state.sync_engine
    th = hash_share_token(body.token)
    link = lookup_share_by_token_hash(eng, th)
    if link is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share not found")
    decision = evaluate_share_access(
        eng,
        link.tenant_id,
        link,
        body.context,
    )
    await get_tenant_event_publisher().publish(
        tenant_id=link.tenant_id,
        event_type=SOCIACL_ACCESS_DECIDED_V1,
        payload=SociaclAccessDecidedPayload(
            tenant_id=link.tenant_id,
            share_id=link.id,
            decision=decision.decision.value,
            reason_code=decision.reason_code,
            actor_sub=body.context.sub,
        ).to_envelope_payload(),
    )
    if decision.decision in (
        SociACLDecisionKind.allow,
        SociACLDecisionKind.notify_owner,
    ):
        decrement_uses(eng, link.tenant_id, link.id)
    return decision


@router.post(
    "/recovery/sessions",
    response_model=RecoverySessionResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def sociacl_recovery_create(
    body: RecoverySessionCreate,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
):
    eng = request.app.state.sync_engine
    row = create_or_get_session(
        eng,
        tenant_id,
        idempotency_key=body.idempotency_key,
        metadata=body.metadata,
    )
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=SOCIACL_RECOVERY_SESSION_STARTED_V1,
        payload=SociaclRecoverySessionPayload(
            tenant_id=tenant_id,
            session_id=row.id,
            state="pending",  # type: ignore[arg-type]
            idempotency_key=row.idempotency_key,
        ).to_envelope_payload(),
    )
    return RecoverySessionResponse(
        session_id=row.id,
        state="pending",
        expires_at=row.expires_at.isoformat(),
    )


@router.post(
    "/recovery/sessions/{session_id}/proof",
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def sociacl_recovery_proof(
    session_id: uuid.UUID,
    body: RecoveryProofRequest,
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    _me: AuthMeResponse = Depends(get_current_user),
):
    _ = body
    eng = request.app.state.sync_engine
    row = transition_state(eng, tenant_id, session_id, "awaiting_proof")
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return {"ok": True, "state": row.state}
