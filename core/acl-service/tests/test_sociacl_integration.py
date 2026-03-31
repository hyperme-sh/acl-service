from __future__ import annotations

import hashlib
import uuid

import pytest
from sqlalchemy import create_engine, text

from api.common.event_types import (
    SOCIACL_ACCESS_DECIDED_V1,
    SOCIACL_RECOVERY_SESSION_STARTED_V1,
    SOCIACL_SHARE_CREATED_V1,
    SOCIACL_SHARE_RESOLVED_V1,
)

pytestmark = pytest.mark.usefixtures("_clean_acl_policies_tenant_a")


@pytest.mark.asyncio
async def test_sociacl_create_resolve_and_events(http_client, tenant_headers, event_sink):
    event_sink.clear()
    cr = await http_client.post(
        "/api/v1/acl/sociacl/shares",
        headers=tenant_headers,
        json={
            "resource_kind": "user",
            "resource_descriptor": {"user_id": str(uuid.uuid4())},
            "predicate": {"min_vouch_count": 1},
            "mode": "release_if_match",
            "max_uses": 10,
        },
    )
    assert cr.status_code == 201, cr.text
    token = cr.json()["token"]
    assert len(token) >= 16
    types = [e["event_type"] for e in event_sink]
    assert SOCIACL_SHARE_CREATED_V1 in types

    event_sink.clear()
    gr = await http_client.get(f"/api/v1/acl/sociacl/shares/by-token/{token}")
    assert gr.status_code == 200
    body = gr.json()
    assert body["active"] is True
    assert body["resource_kind"] == "user"
    types2 = [e["event_type"] for e in event_sink]
    assert SOCIACL_SHARE_RESOLVED_V1 in types2


@pytest.mark.asyncio
async def test_sociacl_evaluate_vouch_negative(http_client, tenant_headers):
    cr = await http_client.post(
        "/api/v1/acl/sociacl/shares",
        headers=tenant_headers,
        json={
            "resource_kind": "user",
            "predicate": {"min_vouch_count": 8},
            "mode": "release_if_match",
        },
    )
    token = cr.json()["token"]
    ev = await http_client.post(
        "/api/v1/acl/sociacl/evaluate",
        json={
            "token": token,
            "context": {"vouch_count": 7},
        },
    )
    assert ev.status_code == 200
    assert ev.json()["decision"] == "deny"
    assert ev.json()["reason_code"] == "vouch_count"


@pytest.mark.asyncio
async def test_sociacl_evaluate_vouch_positive(http_client, tenant_headers):
    cr = await http_client.post(
        "/api/v1/acl/sociacl/shares",
        headers=tenant_headers,
        json={
            "resource_kind": "user",
            "predicate": {"min_vouch_count": 3},
            "mode": "release_if_match",
        },
    )
    token = cr.json()["token"]
    ev = await http_client.post(
        "/api/v1/acl/sociacl/evaluate",
        json={
            "token": token,
            "context": {"vouch_count": 4},
        },
    )
    assert ev.json()["decision"] == "allow"


@pytest.mark.asyncio
async def test_sociacl_handle_blocklist(http_client, tenant_headers):
    cr = await http_client.post(
        "/api/v1/acl/sociacl/shares",
        headers=tenant_headers,
        json={
            "resource_kind": "user",
            "predicate": {"cross_network_handle_blocklist": ["bad"]},
            "mode": "release_if_match",
        },
    )
    token = cr.json()["token"]
    ev = await http_client.post(
        "/api/v1/acl/sociacl/evaluate",
        json={
            "token": token,
            "context": {"cross_network_handle": "bad"},
        },
    )
    assert ev.json()["decision"] == "deny"
    assert ev.json()["reason_code"] == "handle_blocked"


@pytest.mark.asyncio
async def test_sociacl_tenant_isolation_rls(migrated_sync_url, seed, sociacl_rls_role_ready):
    """Tenant A session must not see tenant B sociacl_share_links rows."""
    other = uuid.uuid4()
    unique = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO sociacl_share_links (id, tenant_id, token_hash, token_prefix, "
                "resource_kind, resource_descriptor, predicate_json, mode) "
                "VALUES (:id, :tid, :th, :tp, 'user', '{}'::jsonb, '{}'::jsonb, 'release_if_match')"
            ),
            {
                "id": other,
                "tid": seed.tb,
                "th": unique,
                "tp": unique[:8],
            },
        )
    # Superuser bypasses RLS; enforce policies like the app DB role does.
    with eng.begin() as cx:
        cx.execute(text("SET ROLE sociacl_rls_tester"))
        cx.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(seed.ta)},
        )
        n = cx.execute(
            text("SELECT count(*) FROM sociacl_share_links WHERE id = :id"),
            {"id": other},
        ).scalar_one()
        assert n == 0


@pytest.mark.asyncio
async def test_sociacl_recovery_no_secret_in_db(
    http_client, tenant_headers, migrated_sync_url, seed
):
    r = await http_client.post(
        "/api/v1/acl/sociacl/recovery/sessions",
        headers=tenant_headers,
        json={"idempotency_key": "recovery-test-key-aaaaaaaaaaaa"},
    )
    assert r.status_code == 201
    sid = r.json()["session_id"]
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(seed.ta)},
        )
        row = cx.execute(
            text(
                "SELECT metadata FROM sociacl_recovery_sessions WHERE id = :id "
                "AND tenant_id = :tid"
            ),
            {"id": sid, "tid": seed.ta},
        ).first()
        assert row is not None
        meta = row[0]
        assert meta is None or "secret" not in str(meta).lower()


@pytest.mark.asyncio
async def test_recovery_emits_event(http_client, tenant_headers, event_sink):
    event_sink.clear()
    r = await http_client.post(
        "/api/v1/acl/sociacl/recovery/sessions",
        headers=tenant_headers,
        json={"idempotency_key": "recovery-test-key-bbbbbbbbbbbb"},
    )
    assert r.status_code == 201
    assert SOCIACL_RECOVERY_SESSION_STARTED_V1 in [e["event_type"] for e in event_sink]


@pytest.mark.asyncio
async def test_evaluate_emits_access_decided(http_client, tenant_headers, event_sink):
    cr = await http_client.post(
        "/api/v1/acl/sociacl/shares",
        headers=tenant_headers,
        json={
            "resource_kind": "user",
            "predicate": {},
            "mode": "release_if_match",
        },
    )
    token = cr.json()["token"]
    event_sink.clear()
    await http_client.post(
        "/api/v1/acl/sociacl/evaluate",
        json={"token": token, "context": {}},
    )
    assert SOCIACL_ACCESS_DECIDED_V1 in [e["event_type"] for e in event_sink]
