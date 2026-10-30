"""Domain ABAC/RBAC scenarios: marketplace listings, restricted purchase, AI budget."""

from __future__ import annotations

import uuid

import pytest

from acl_service.infrastructure.domain_policy_loader import (
    policy_row_abac_ai_invoke_budget,
    policy_row_abac_own_listing_manage,
    policy_row_abac_restricted_purchase,
    policy_rows_marketplace_seller_via_group,
)

pytestmark = pytest.mark.usefixtures("_clean_acl_policies_tenant_a")


@pytest.mark.asyncio
async def test_marketplace_seller_role_can_create_via_group(http_client, tenant_headers):
    uid = str(uuid.uuid4())
    sub = f"user:{uid}"
    for row in policy_rows_marketplace_seller_via_group(uid):
        ptype, rule = row
        r = await http_client.post(
            "/api/v1/acl/policies",
            headers=tenant_headers,
            json={"ptype": ptype, "rule": rule},
        )
        assert r.status_code == 201
    ok = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": sub,
            "obj": "/marketplace/listings",
            "act": "create",
        },
    )
    assert ok.json()["allow"] is True


@pytest.mark.asyncio
async def test_seller_abac_update_own_listing_only(http_client, tenant_headers):
    seller = uuid.uuid4()
    other = uuid.uuid4()
    sub = f"user:{seller}"
    ptype, rule = policy_row_abac_own_listing_manage(seller, "update")
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": ptype, "rule": rule},
    )
    allow = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": sub,
            "obj": "/marketplace/listings",
            "act": "update",
            "extra": str(seller),
        },
    )
    assert allow.json()["allow"] is True
    deny = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": f"user:{other}",
            "obj": "/marketplace/listings",
            "act": "update",
            "extra": str(seller),
        },
    )
    assert deny.json()["allow"] is False


@pytest.mark.asyncio
async def test_restricted_purchase_requires_matching_extra(http_client, tenant_headers):
    ptype, rule = policy_row_abac_restricted_purchase("military_ok")
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": ptype, "rule": rule},
    )
    buyer = uuid.uuid4()
    ok = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": f"user:{buyer}",
            "obj": "/marketplace/restricted",
            "act": "purchase",
            "extra": "military_ok",
        },
    )
    assert ok.json()["allow"] is True
    bad = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": f"user:{buyer}",
            "obj": "/marketplace/restricted",
            "act": "purchase",
            "extra": "civilian",
        },
    )
    assert bad.json()["allow"] is False


@pytest.mark.asyncio
async def test_ai_invoke_budget_extra_must_match(http_client, tenant_headers):
    uid = uuid.uuid4()
    budget_id = uuid.uuid4()
    sub = f"user:{uid}"
    ptype, rule = policy_row_abac_ai_invoke_budget(sub, budget_id)
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": ptype, "rule": rule},
    )
    ok = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": sub,
            "obj": "/ai/inference",
            "act": "invoke",
            "extra": f"budget:{budget_id}",
        },
    )
    assert ok.json()["allow"] is True
    wrong_budget = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": sub,
            "obj": "/ai/inference",
            "act": "invoke",
            "extra": f"budget:{uuid.uuid4()}",
        },
    )
    assert wrong_budget.json()["allow"] is False


@pytest.mark.asyncio
async def test_abac_missing_extra_denies(http_client, tenant_headers):
    r = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": "user:x",
            "obj": "/ai/inference",
            "act": "invoke",
        },
    )
    assert r.status_code == 200
    assert r.json()["allow"] is False
