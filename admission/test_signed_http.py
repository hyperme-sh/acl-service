"""HTTP qualification using the merged verifier, real SQLite and synthetic signatures."""
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from auth_service.schemas import AuthMeResponse
from acl_service.app import create_app
from acl_service import deps
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.interfaces.api.signed_store_routes import SignedStoreBinding
from api.core import config as api_config
from asgi_lifespan import LifespanManager
from history_admission import EnrollmentGrant, HistoryAdmission


@pytest.mark.asyncio
async def test_scoped_signed_write_http(tmp_path, migrated_sync_url, monkeypatch):
    base = Path(__file__).parent
    f = json.loads((base / "fixture.json").read_bytes())
    ops = json.loads((base / "store-fixture.json").read_bytes())
    store = SqliteHistoryStore(tmp_path / "http.db")
    principal = f["genesis"]
    grant = EnrollmentGrant(principal, "qualification", "one-use-grant", f["now"] + 60)
    writer = HistoryAdmission(store, grant_for=lambda _: grant, clock=lambda: f["now"],
                              trust_at=lambda _: {k: f[k] for k in ("policy", "jwks", "pinnedIss")})
    writer.enroll(principal, json.dumps(f["binding"]).encode(), f["signature"])
    tenant, other = uuid4(), uuid4()
    monkeypatch.setattr(api_config.settings, "database_url", migrated_sync_url.replace("+psycopg", ""))
    monkeypatch.setattr(api_config.settings, "acl_rate_limit_per_minute", 100)
    app = create_app(test_event_sink=[], signed_store_bindings={(tenant, "owner"): SignedStoreBinding(principal, writer)})
    actor = AuthMeResponse(sub="owner", tenant_id=tenant)
    app.dependency_overrides[deps.get_current_user] = lambda: actor
    app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: actor.tenant_id
    path = "/api/v1/acl/sociacl/keyring"
    async with LifespanManager(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://acl") as client:
        client.headers["X-Tenant-ID"] = str(other)
        assert (await client.post(path + "/wraps/operations", json=ops["wrap"])).status_code == 403
        actor = AuthMeResponse(sub="owner", tenant_id=other)
        assert (await client.post(path + "/wraps/operations", json=ops["wrap"])).status_code == 403
        client.headers["X-Tenant-ID"] = str(tenant)
        actor = AuthMeResponse(sub="stranger", tenant_id=tenant)
        assert (await client.post(path + "/wraps/operations", json=ops["wrap"])).status_code == 403
        actor = AuthMeResponse(sub="owner", tenant_id=tenant)
        target = ops["wrap"]["row"]["wrapId"]
        actor = AuthMeResponse(sub="stranger", tenant_id=tenant)
        assert (await client.get(f"{path}/wraps/rows/{target}")).status_code == 403
        actor = AuthMeResponse(sub="owner", tenant_id=tenant)
        for raw, code in ((b'{"action":"put","action":"delete"}', 400),
                          (b'{"n":1e999}', 400), (b"x" * (2 * 1024 * 1024 + 1), 413)):
            response = await client.post(path + "/wraps/operations", content=raw,
                                         headers={"Content-Type": "application/json"})
            assert response.status_code == code
        for invalid in (dict(ops["wrap"], principal=principal), dict(ops["wrap"], signature="ff"*64)):
            assert (await client.post(path + "/wraps/operations", json=invalid)).status_code == 403
        assert store.read_ciphertext(principal, "wraps") == (0, b"")
        for kind, name in (("wraps", "wrap"), ("recovery", "current")):
            response = await client.post(f"{path}/{kind}/operations", json=ops[name])
            assert response.status_code == 200 and response.json() == {"generation": 1}
            slot = target if kind == "wraps" else "current"
            reread = await client.get(f"{path}/{kind}/rows/{slot}")
            assert reread.status_code == 200 and reread.headers["cache-control"] == "no-store"
            assert reread.json()["row"] == ops[name]["row"] and reread.json()["generation"] == 1
            assert (await client.post(f"{path}/{kind}/operations", json=ops[name])).status_code == 403
            assert store.read_ciphertext(principal, kind)[0] == 1
        app.state.signed_store_bindings = None
        assert (await client.post(path + "/wraps/operations", json=ops["deleteWrap"])).status_code == 503
        app.dependency_overrides.clear()
        response = await client.post(path + "/wraps/operations", json=ops["deleteWrap"])
        assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_lost_recovery_responses_across_application_restarts(tmp_path, migrated_sync_url, monkeypatch):
    """Only HTTP read-back tells the caller whether each ambiguous commit persisted."""
    from contextlib import asynccontextmanager
    from hashlib import sha256

    from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

    base = Path(__file__).parent
    identity = json.loads((base / "fixture.json").read_bytes())
    operations = json.loads((base / "store-fixture.json").read_bytes())
    principal = identity["genesis"]
    tenant = uuid4()
    database = tmp_path / "history.sqlite"
    anchor = tmp_path / "freshness.sqlite"
    grant = EnrollmentGrant(principal, "qualification", "one-use-grant", identity["now"] + 60)
    trust = {k: identity[k] for k in ("policy", "jwks", "pinnedIss")}
    def writer(store):
        return HistoryAdmission(store, grant_for=lambda _: grant, clock=lambda: identity["now"],
                                trust_at=lambda _: trust)

    initial = writer(SqliteHistoryStore(database))
    initial.enroll(principal, json.dumps(identity["binding"]).encode(), identity["signature"])
    initialize(database, sha256(database.read_bytes()).hexdigest(), anchor)
    monkeypatch.setattr(api_config.settings, "database_url", migrated_sync_url.replace("+psycopg", ""))

    class LoseWriteResponse(httpx.ASGITransport):
        async def handle_async_request(self, request):
            response = await super().handle_async_request(request)
            if request.method == "POST":
                await response.aclose()
                raise httpx.ReadError("synthetic return-path loss", request=request)
            return response

    @asynccontextmanager
    async def restart():
        adapter = writer(SqliteHistoryStore(database, freshness_path=anchor, require_authority_checkpoint=True))
        app = create_app(test_event_sink=[], signed_store_bindings={
            (tenant, "owner"): SignedStoreBinding(principal, adapter)})
        app.dependency_overrides[deps.get_current_user] = lambda: AuthMeResponse(sub="owner", tenant_id=tenant)
        app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: tenant
        async with LifespanManager(app), httpx.AsyncClient(
            transport=LoseWriteResponse(app=app), base_url="http://acl/api/v1/acl/sociacl/keyring/recovery/",
            headers={"X-Tenant-ID": str(tenant)},
        ) as client:
            yield client, adapter

    async def lost(client, name):
        with pytest.raises(httpx.ReadError, match="synthetic return-path loss"):
            await client.post("operations", json=operations[name])

    async def expect(client, generation, current, pending):
        for slot, name in (("current", current), ("pending", pending)):
            response = await client.get("rows/" + slot)
            assert response.status_code == 200
            state = response.json()
            assert state["generation"] == generation
            assert state["row"] == (operations[name]["row"] if name else None)

    async with restart() as (client, _):
        await lost(client, "current")
    async with restart() as (client, _):
        await expect(client, 1, "current", None)
        await lost(client, "pending")
    async with restart() as (client, adapter):
        await expect(client, 2, "current", "pending")
        for name in ("wallet", "rotate-v4-wallet"):
            adapter.admit(principal, json.dumps(identity[name]).encode())
        await lost(client, "commit")
    async with restart() as (client, _):
        await expect(client, 3, "pending", None)
        await lost(client, "deleteCommitted")
    async with restart() as (client, _):
        await expect(client, 4, None, None)
