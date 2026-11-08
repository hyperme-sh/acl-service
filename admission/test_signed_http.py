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


@pytest.mark.asyncio
async def test_genesis_wrap_recipient_opens_http_readback(tmp_path, migrated_sync_url, monkeypatch):
    import subprocess

    base = Path(__file__).parent
    identity = json.loads((base / "fixture.json").read_bytes())
    principal = identity["genesis"]
    store = SqliteHistoryStore(tmp_path / "genesis-wrap.sqlite")
    grant = EnrollmentGrant(principal, "qualification", "one-use-grant", identity["now"] + 60)
    writer = HistoryAdmission(store, grant_for=lambda _: grant, clock=lambda: identity["now"],
                              trust_at=lambda _: {k: identity[k] for k in ("policy", "jwks", "pinnedIss")})
    writer.enroll(principal, json.dumps(identity["binding"]).encode(), identity["signature"])
    tenant = uuid4()
    monkeypatch.setattr(api_config.settings, "database_url", migrated_sync_url.replace("+psycopg", ""))
    app = create_app(test_event_sink=[], signed_store_bindings={
        (tenant, "owner"): SignedStoreBinding(principal, writer)})
    app.dependency_overrides[deps.get_current_user] = lambda: AuthMeResponse(sub="owner", tenant_id=tenant)
    app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: tenant
    harness = ["node", str(base / "genesis-wrap-client.mjs")]
    operation = json.loads(subprocess.check_output([*harness, "seal"]))
    async with LifespanManager(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://acl/api/v1/acl/sociacl/keyring/wraps/",
        headers={"X-Tenant-ID": str(tenant)},
    ) as client:
        write = await client.post("operations", json=operation)
        assert write.status_code == 200 and write.json() == {"generation": 1}
        readback = await client.get("rows/" + operation["row"]["wrapId"])
        assert readback.status_code == 200
        state = readback.json()
        assert state["generation"] == 1 and state["row"] == operation["row"]
        subprocess.run([*harness, "open"], input=json.dumps(state["row"]).encode(), check=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["recovery", "wraps"])
async def test_last_generation_contention_and_ledger_rollback(tmp_path, migrated_sync_url, monkeypatch, kind):
    import asyncio
    import hashlib
    import shutil
    import sqlite3

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from acl_service.domain.keyring_store import MAX_GENERATION
    from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

    base = Path(__file__).parent
    identity = json.loads((base / "fixture.json").read_bytes())
    ops = json.loads((base / "store-fixture.json").read_bytes())
    principal = identity["genesis"]
    db = tmp_path / "ledger.sqlite"
    anchor = tmp_path / "freshness.sqlite"
    snapshot = tmp_path / "penultimate.sqlite"
    grant = EnrollmentGrant(principal, "qualification", "one-use-grant", identity["now"] + 60)
    writer = HistoryAdmission(SqliteHistoryStore(db), grant_for=lambda _: grant, clock=lambda: identity["now"],
                              trust_at=lambda _: {k: identity[k] for k in ("policy", "jwks", "pinnedIss")})
    writer.enroll(principal, json.dumps(identity["binding"]).encode(), identity["signature"])
    writer.observe_store_head(principal)
    # Seed the disposable fixture immediately before exhaustion. All subsequent
    # writes, races and observations go through the application.
    with sqlite3.connect(db) as cx:
        cx.execute("INSERT INTO history_ciphertext VALUES(?,?,?,?)", (principal, kind, MAX_GENERATION - 1, b"{}"))
    shutil.copyfile(db, snapshot)
    initialize(snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest(), anchor)
    writer.store = SqliteHistoryStore(db, freshness_path=anchor, require_authority_checkpoint=True)
    row = ops["wrap" if kind == "wraps" else "current"]["row"]

    def encode(*fields):
        parts = [str(field).encode() for field in fields]
        return b"".join(len(part).to_bytes(4, "little") + part for part in parts)

    if kind == "wraps":
        slot = target = row["wrapId"]
        category = row["class"]
        content = encode("sociacl-wrap-row-v1", principal, target, row["epub"], category,
                         row["ciphertextHex"], row["signature"])
    else:
        slot, target, category = "current", row["rotationSeq"], "none"
        content = encode(principal, target, row["signingPub"], row["epub"], row["bytesHex"])
    digest = hashlib.sha256(content).hexdigest()

    def put(generation, predecessor):
        message = encode("sociacl-store-write-v1", principal, "put", target, digest, 0, predecessor, category, generation)
        key = ec.derive_private_key(1, ec.SECP256R1())  # Public admission fixture.
        r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        return dict(action="put", row=row, signature=f"{r:064x}{min(s, order-s):064x}")

    tenant = uuid4()
    monkeypatch.setattr(api_config.settings, "database_url", migrated_sync_url.replace("+psycopg", ""))
    app = create_app(test_event_sink=[], signed_store_bindings={
        (tenant, "owner"): SignedStoreBinding(principal, writer)})
    app.dependency_overrides[deps.get_current_user] = lambda: AuthMeResponse(sub="owner", tenant_id=tenant)
    app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: tenant
    async with LifespanManager(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://acl/api/v1/acl/sociacl/keyring/{kind}/",
        headers={"X-Tenant-ID": str(tenant)},
    ) as client:
        operation = put(MAX_GENERATION - 1, "none")
        responses = await asyncio.gather(*(client.post("operations", json=operation) for _ in range(2)))
        success, rejected = sorted(responses, key=lambda result: result.status_code)
        assert success.status_code == 200 and success.json() == {"generation": MAX_GENERATION}
        assert rejected.status_code in (403, 409)
        final = await client.get("rows/" + slot)
        assert final.status_code == 200
        assert (final.json()["generation"], final.json()["row"]) == (MAX_GENERATION, row)
        assert (await client.post("operations", json=put(MAX_GENERATION, digest))).status_code == 403
        assert (await client.get("rows/" + slot)).json() == final.json()

        # Restore only the closed ledger file. The independent anchor still
        # records the winning commit and must prevent the old write being reused.
        shutil.copyfile(snapshot, db)
        assert (await client.get("rows/" + slot)).status_code == 409
        assert (await client.post("operations", json=operation)).status_code == 409
