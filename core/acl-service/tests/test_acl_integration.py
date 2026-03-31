from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from api.common.event_types import ACL_POLICY_UPDATED_V1
from auth_service.deps import get_current_tenant, get_current_user
from auth_service.schemas import AuthMeResponse

pytestmark = pytest.mark.usefixtures("_clean_acl_policies_tenant_a")


@pytest.mark.asyncio
async def test_rbac_enforce_allow(http_client, tenant_headers, seed, app):
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": "g", "rule": ["alice", "data_admin"]},
    )
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": "p", "rule": ["data_admin", "data1", "read"]},
    )
    r = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": "alice",
            "obj": "data1",
            "act": "read",
        },
    )
    assert r.status_code == 200
    assert r.json()["allow"] is True


@pytest.mark.asyncio
async def test_rbac_enforce_deny(http_client, tenant_headers):
    r = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": "nobody",
            "obj": "data1",
            "act": "read",
        },
    )
    assert r.status_code == 200
    assert r.json()["allow"] is False


@pytest.mark.asyncio
async def test_abac_political_positive_negative(http_client, tenant_headers):
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={
            "ptype": "p",
            "rule": ["alice", "attr:political_view", "read", "other"],
        },
    )
    ok = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": "alice",
            "obj": "attr:political_view",
            "act": "read",
            "extra": "other",
        },
    )
    assert ok.status_code == 200
    assert ok.json()["allow"] is True
    bad = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "abac",
            "sub": "alice",
            "obj": "attr:political_view",
            "act": "read",
            "extra": "unspecified",
        },
    )
    assert bad.json()["allow"] is False


@pytest.mark.asyncio
async def test_dynamic_policy_update(http_client, tenant_headers):
    r1 = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": "bob",
            "obj": "x", "act": "read",
        },
    )
    assert r1.json()["allow"] is False
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": "p", "rule": ["bob", "x", "read"]},
    )
    r2 = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": "bob",
            "obj": "x", "act": "read",
        },
    )
    assert r2.json()["allow"] is True


@pytest.mark.asyncio
async def test_tenant_isolation_enforce(migrated_sync_url, seed, tenant_headers, http_client):
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO acl_casbin_rules (tenant_id, ptype, v0, v1, v2) "
                "VALUES (:tid, 'p', 'eve', 'secret', 'read')"
            ),
            {"tid": seed.tb},
        )
    r = await http_client.post(
        "/api/v1/acl/enforce",
        headers=tenant_headers,
        json={
            "model": "rbac",
            "sub": "eve",
            "obj": "secret",
            "act": "read",
        },
    )
    assert r.json()["allow"] is False


@pytest.mark.asyncio
async def test_require_permission_403_then_allow(http_client, tenant_headers, auth_context):
    _user, _tenant, sub = auth_context
    r = await http_client.get("/api/v1/acl/protected-ping", headers=tenant_headers)
    assert r.status_code == 403
    await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={
            "ptype": "p",
            "rule": [f"user:{sub}", "/acl/protected-ping", "read"],
        },
    )
    r2 = await http_client.get("/api/v1/acl/protected-ping", headers=tenant_headers)
    assert r2.status_code == 200
    assert r2.json() == {"ok": True}


@pytest.mark.asyncio
async def test_policy_create_emits_kafka_event(http_client, tenant_headers, event_sink):
    event_sink.clear()
    r = await http_client.post(
        "/api/v1/acl/policies",
        headers=tenant_headers,
        json={"ptype": "p", "rule": ["z", "z1", "read"]},
    )
    assert r.status_code == 201
    types = [e["event_type"] for e in event_sink]
    assert ACL_POLICY_UPDATED_V1 in types
