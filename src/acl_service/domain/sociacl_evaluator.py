"""SociACL predicate evaluation; composes with Casbin for optional RBAC gates."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from typing import Protocol

from acl_service.domain.membership_reader import MembershipReader
from acl_service.domain.policy_store import PolicyStore
from spanopticon_models.sociacl import (
    SociACLDecision,
    SociACLDecisionKind,
    SociACLRequestContext,
    SociACLShareMode,
    SociACLPredicate,
)

from acl_service.infrastructure.enforcer_factory import enforce_rbac


class SharePolicyView(Protocol):
    revoked_at: datetime | None
    expires_at: datetime | None
    uses_remaining: int | None
    predicate_json: dict
    mode: str


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _share_active(link: SharePolicyView, now: datetime) -> tuple[bool, str]:
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
    memberships: MembershipReader,
    tenant_id: uuid.UUID,
    link: SharePolicyView,
    ctx: SociACLRequestContext,
    *,
    authenticated_sub: str | None = None,
    require_casbin_sociacl_gate: bool = False,
    casbin_sub: str | None = None,
    policy_store: PolicyStore | None = None,
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

    if require_casbin_sociacl_gate:
        ok = bool(casbin_sub) and policy_store is not None and enforce_rbac(
            policy_store,
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
        if not _user_in_group(memberships, tenant_id, authenticated_sub, pred.member_of_group_id):
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
    memberships: MembershipReader, tenant_id: uuid.UUID, subject: str, group_id: uuid.UUID,
) -> bool:
    return memberships is not None and memberships.user_in_group(tenant_id, subject, group_id)
