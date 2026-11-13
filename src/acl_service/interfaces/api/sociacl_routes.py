from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from controlplane_api.event_types import (
    SOCIACL_ACCESS_DECIDED_V1,
    SOCIACL_RECOVERY_SESSION_STARTED_V1,
    SOCIACL_SHARE_CREATED_V1,
    SOCIACL_SHARE_RESOLVED_V1,
)
from acl_service.infrastructure.atomic import atomic_store
from auth_service.schemas import AuthMeResponse
from controlplane_events.payloads import (
    SociaclAccessDecidedPayload,
    SociaclRecoverySessionPayload,
    SociaclShareCreatedPayload,
    SociaclShareResolvedPayload,
)
from spanopticon_models.sociacl import (
    RecoveryProofRequest,
    RecoverySessionCreate,
    RecoverySessionResponse,
    SociACLEvaluateRequest,
    SociACLPredicate,
    SociACLShareLinkCreate,
    SociACLShareLinkOwnerView,
    SociACLShareLinkPublic,
    SociACLDecision,
    SociACLDecisionKind,
    SociACLResourceKind,
    SociACLShareMode,
)

from acl_service.deps import get_current_user, require_matched_tenant, optional_authenticated_user
from acl_service.domain.dtos import SociaclShareCreatedResponse
from acl_service.domain.sociacl_evaluator import _share_active, evaluate_share_access
from acl_service.domain.recovery_store import RecoveryStore
from acl_service.domain.share_store import (
    create_share,
    decrement_uses,
    hash_share_token,
    list_shares,
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


def _owner_payload(link) -> SociACLShareLinkOwnerView:
    pub = _public_payload(link)
    try:
        pred = SociACLPredicate.model_validate(link.predicate_json)
    except Exception:
        pred = SociACLPredicate()
    created = link.created_at.isoformat() if link.created_at else None
    return SociACLShareLinkOwnerView(
        share_id=pub.share_id,
        token_prefix=link.token_prefix,
        mode=pub.mode,
        active=pub.active,
        resource_kind=pub.resource_kind,
        resource_descriptor=link.resource_descriptor or {},
        predicate=pred,
        expires_at=pub.expires_at,
        uses_remaining=pub.uses_remaining,
        owner_user_id=link.owner_user_id,
        group_id=link.group_id,
        created_by=link.created_by,
        created_at=created,
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
    store = request.app.state.share_store
    def _run():
        with atomic_store(store) as tx:
            store_bound = tx.store
            exp = _parse_expires_iso(body.expires_at)
            row, raw_token = create_share(store_bound, tenant_id=tenant_id, resource_kind=body.resource_kind.value, resource_descriptor=body.resource_descriptor, predicate_json=body.predicate.model_dump(mode='json'), mode=body.mode.value, expires_at=exp, uses_remaining=body.max_uses, owner_user_id=body.owner_user_id, group_id=body.group_id, created_by=str(me.sub))
            pub = _public_payload(row)
            tx.emit(tenant_id=tenant_id, event_type=SOCIACL_SHARE_CREATED_V1, payload=SociaclShareCreatedPayload(tenant_id=tenant_id, share_id=row.id, mode=body.mode.value, resource_kind=body.resource_kind.value, token_prefix=row.token_prefix, actor_sub=str(me.sub)).to_envelope_payload(), operation_id=str(row.id))
            return SociaclShareCreatedResponse(share_id=row.id, token=raw_token, public=pub)
    return await asyncio.to_thread(_run)


@router.get(
    "/shares",
    response_model=list[SociACLShareLinkOwnerView],
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def sociacl_list_shares(
    request: Request,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
):
    store = request.app.state.share_store
    if not me.sub:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Verified subject required")

    def _run():
        from acl_service.infrastructure.enforcer_factory import enforce_rbac
        manager = enforce_rbac(request.app.state.policy_store, tenant_id,
                               f"user:{me.sub}", "/acl/sociacl/shares", "manage")
        return list_shares(store, tenant_id, creator_sub=None if manager else str(me.sub))

    rows = await asyncio.to_thread(_run)
    return [_owner_payload(r) for r in rows]


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
    store = request.app.state.share_store
    def _run():
        with atomic_store(store) as tx:
            store_bound = tx.store
            th = hash_share_token(token)
            link = lookup_share_by_token_hash(store_bound, th)
            if link is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Share not found')
            pub = _public_payload(link)
            tx.emit(tenant_id=link.tenant_id, event_type=SOCIACL_SHARE_RESOLVED_V1, payload=SociaclShareResolvedPayload(tenant_id=link.tenant_id, share_id=link.id, active=pub.active, actor_sub=None).to_envelope_payload(), operation_id=str(uuid.uuid4()))
            return pub
    return await asyncio.to_thread(_run)


@router.post("/evaluate", response_model=SociACLDecision)
async def sociacl_evaluate(
    body: SociACLEvaluateRequest, request: Request,
    me: AuthMeResponse | None = Depends(optional_authenticated_user),
):
    ip = _client_ip(request)
    if not _public_rl.allow(f"eval:{ip}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
    store = request.app.state.share_store
    def _run():
        with atomic_store(store) as tx:
            store_bound = tx.store
            th = hash_share_token(body.token)
            link = lookup_share_by_token_hash(store_bound, th)
            if link is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Share not found')
            from acl_service.infrastructure.membership_reader import PostgresMembershipReader
            reader = request.app.state.membership_reader
            if isinstance(reader, PostgresMembershipReader):
                reader = PostgresMembershipReader(tx.connection)
            decision = evaluate_share_access(reader, link.tenant_id, link, body.context, authenticated_sub=me.sub if me is not None and me.tenant_id == link.tenant_id else None)
            if decision.decision in (SociACLDecisionKind.allow, SociACLDecisionKind.notify_owner):
                reserved = decrement_uses(store_bound, link.tenant_id, link.id)
                if not reserved:
                    decision = SociACLDecision(decision=SociACLDecisionKind.deny, reason_code='share_unavailable', matched_predicates=[])
            tx.emit(tenant_id=link.tenant_id, event_type=SOCIACL_ACCESS_DECIDED_V1, payload=SociaclAccessDecidedPayload(tenant_id=link.tenant_id, share_id=link.id, decision=decision.decision.value, reason_code=decision.reason_code, actor_sub=me.sub if me is not None and me.tenant_id == link.tenant_id else None).to_envelope_payload(), operation_id=str(uuid.uuid4()))
            return decision
    return await asyncio.to_thread(_run)


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
    store: RecoveryStore = request.app.state.recovery_store
    def _run():
        with atomic_store(store) as tx:
            store_bound = tx.store
            row = store_bound.create_or_get_session(tenant_id, idempotency_key=body.idempotency_key, metadata=body.metadata)
            tx.emit(tenant_id=tenant_id, event_type=SOCIACL_RECOVERY_SESSION_STARTED_V1, payload=SociaclRecoverySessionPayload(tenant_id=tenant_id, session_id=row.id, state='pending', idempotency_key=row.idempotency_key).to_envelope_payload(), operation_id=str(row.id))
            return RecoverySessionResponse(session_id=row.id, state=row.state, expires_at=row.expires_at.isoformat())
    return await asyncio.to_thread(_run)


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
    store: RecoveryStore = request.app.state.recovery_store
    row = await asyncio.to_thread(store.transition_state, tenant_id, session_id, "awaiting_proof")
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return {"ok": True, "state": row.state}
