"""Recommended Casbin tuples for marketplace + AI domains (reference + test seeding).

RBAC uses model_rbac.conf (sub, obj, act). ABAC uses model_abac.conf (sub, obj, act, pol_req).

Tenants typically insert rows via POST /api/v1/acl/policies or migrations.
"""

from __future__ import annotations

import uuid

from sqlalchemy.engine import Engine

from acl_service.infrastructure.policy_repo import add_rule

# Casbin "group" name linking users to marketplace capabilities
ROLE_MARKETPLACE_SELLER = "role_marketplace_seller"


def policy_rows_marketplace_seller_via_group(user_sub: str) -> list[tuple[str, list[str]]]:
    """g assigns user → role; p grants role create/purchase on listings."""
    u = user_sub if user_sub.startswith("user:") else f"user:{user_sub}"
    return [
        ("g", [u, ROLE_MARKETPLACE_SELLER]),
        ("p", [ROLE_MARKETPLACE_SELLER, "/marketplace/listings", "create"]),
        ("p", [ROLE_MARKETPLACE_SELLER, "/marketplace/listings", "purchase"]),
    ]


def policy_row_abac_own_listing_manage(user_uuid: uuid.UUID, act: str) -> tuple[str, list[str]]:
    """ABAC: only this subject may act on /marketplace/listings with pol_req = seller uuid."""
    s = f"user:{user_uuid}"
    su = str(user_uuid)
    return ("p", [s, "/marketplace/listings", act, su])


def policy_row_abac_restricted_purchase(attr_token: str = "military_ok") -> tuple[str, list[str]]:
    """ABAC: buyer must present matching extra (e.g. SociACL-derived attribute)."""
    return (
        "p",
        ["*", "/marketplace/restricted", "purchase", attr_token],
    )


def policy_row_abac_ai_invoke_budget(user_sub: str, budget_id: uuid.UUID) -> tuple[str, list[str]]:
    """ABAC: invoke AI only when extra matches budget:<id> (agent spend scope)."""
    u = user_sub if user_sub.startswith("user:") else f"user:{user_sub}"
    return ("p", [u, "/ai/inference", "invoke", f"budget:{budget_id}"])


def seed_policies(
    sync_engine: Engine,
    tenant_id: uuid.UUID,
    rows: list[tuple[str, list[str]]],
) -> None:
    """Insert policy rows (idempotent only if caller dedupes)."""
    for ptype, rule in rows:
        add_rule(sync_engine, tenant_id, ptype, rule)
