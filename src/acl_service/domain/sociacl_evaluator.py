"""SociACL predicate evaluation; composes with Casbin for optional RBAC gates."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select, text
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclShareLink, User, UserGroupMembership
from panopticon_models.sociacl import (
    SociACLDecision,
    SociACLDecisionKind,
    SociACLRequestContext,
    SociACLShareMode,
    SociACLPredicate,
)

from acl_service.infrastructure.enforcer_factory import enforce_rbac


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _share_active(link: SociaclShareLink, now: datetime) -> tuple[bool, str]:
    if link.revoked_at is not None:
        return False, "revoked"
    exp = _normalize_utc(link.expires_at)
    if exp is not None and exp <= now:
        return False, "expired"
    if link.uses_remaining is not None and link.uses_remaining <= 0:
        return False, "no_uses"
    return True, "ok"


def evaluate_predicates(
    pred: SociACLPredicate,
    ctx: SociACLRequestContext,
) -> tuple[bool, str, list[str]]:
    """Returns (ok, reason_code, matched_rule_names)."""
    matched: list[str] = []

    # Request context is self-asserted, even for authenticated callers.
    # No trusted same-tenant attribute/attestation resolver is wired here yet.
    if pred.min_verification_level is not None or pred.min_vouch_count is not None:
        return False, "verified_identity_attributes_required", matched

    if (
        pred.max_distance_km is not None
        or pred.required_political_tolerance is not None
        or pred.cross_network_handle_allowlist is not None
        or pred.cross_network_handle_blocklist is not None
    ):
        return False, "verified_predicate_evidence_required", matched

    return True, "ok", matched


def evaluate_share_access(
    sync_engine,
    tenant_id: uuid.UUID,
    link: SociaclShareLink,
    ctx: SociACLRequestContext,
    *,
    authenticated_sub: str | None = None,
    require_casbin_sociacl_gate: bool = False,
    casbin_sub: str | None = None,
) -> SociACLDecision:
    """
    Evaluate SociACL for a share row. Optional Casbin gate: resource ``sociacl:share``, action ``evaluate``.
    """
    now = _now_utc()
    active, why = _share_active(link, now)
    if not active:
        return SociACLDecision(
            decision=SociACLDecisionKind.deny,
            reason_code=why,
            matched_predicates=[],
        )

    try:
        pred = SociACLPredicate.model_validate(link.predicate_json)
    except Exception:
        return SociACLDecision(
            decision=SociACLDecisionKind.deny,
            reason_code="invalid_predicate",
            matched_predicates=[],
        )

    if require_casbin_sociacl_gate and casbin_sub:
        ok = enforce_rbac(
            sync_engine,
            tenant_id,
            casbin_sub,
            "sociacl:share",
            "evaluate",
        )
        if not ok:
            return SociACLDecision(
                decision=SociACLDecisionKind.deny,
                reason_code="casbin_denied",
                matched_predicates=[],
            )

    ok, reason, matched = evaluate_predicates(pred, ctx)
    if not ok:
        return SociACLDecision(
            decision=SociACLDecisionKind.deny,
            reason_code=reason,
            matched_predicates=[],
        )

    if pred.member_of_group_id is not None:
        if not authenticated_sub:
            return SociACLDecision(
                decision=SociACLDecisionKind.deny,
                reason_code="sub_required_for_group",
                matched_predicates=[],
            )
        if not _user_in_group(sync_engine, tenant_id, authenticated_sub, pred.member_of_group_id):
            return SociACLDecision(
                decision=SociACLDecisionKind.deny,
                reason_code="not_group_member",
                matched_predicates=[],
            )
        matched.append("member_of_group_id")

    mode = SociACLShareMode(link.mode)
    if mode == SociACLShareMode.notify_only:
        return SociACLDecision(
            decision=SociACLDecisionKind.notify_owner,
            reason_code="notify_only_mode",
            matched_predicates=matched,
        )
    if mode == SociACLShareMode.negotiate:
        return SociACLDecision(
            decision=SociACLDecisionKind.challenge,
            reason_code="negotiate_mode",
            matched_predicates=matched,
        )
    return SociACLDecision(
        decision=SociACLDecisionKind.allow,
        reason_code="released",
        matched_predicates=matched,
    )


def _user_in_group(
    sync_engine, tenant_id: uuid.UUID, subject: str, group_id: uuid.UUID
) -> bool:
    with Session(sync_engine) as session:
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        row = session.scalars(
            select(UserGroupMembership).join(User, User.id == UserGroupMembership.user_id).where(
                and_(
                    UserGroupMembership.tenant_id == tenant_id,
                    User.tenant_id == tenant_id,
                    User.keycloak_sub == subject,
                    User.is_active.is_(True),
                    User.deleted_at.is_(None),
                    UserGroupMembership.group_id == group_id,
                )
            )
        ).first()
        return row is not None
