from __future__ import annotations

import os
import uuid
from collections import namedtuple

import pytest
from sqlalchemy import create_engine, text

from api.core import config as api_config
from api.infrastructure.security import keycloak_jwt as kc_jwt
from auth_service.deps import get_current_tenant, get_current_user
from auth_service.schemas import AuthMeResponse
from panopticon_tests.fixtures.postgres import (
    normalize_sync_sqlalchemy_url,
    run_alembic_upgrade,
)
from testcontainers.postgres import PostgresContainer

Seed = namedtuple("Seed", ["ta", "tb"])


@pytest.fixture(autouse=True)
def _clear_keycloak_validator_cache() -> None:
    kc_jwt._validator_singleton.cache_clear()
    yield
    kc_jwt._validator_singleton.cache_clear()


@pytest.fixture(scope="session")
def require_docker() -> None:
    if os.environ.get("SKIP_TESTCONTAINERS", "").lower() in ("1", "true", "yes"):
        pytest.skip("SKIP_TESTCONTAINERS is set")
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker not available for testcontainers: {exc}")


@pytest.fixture(scope="session")
def postgres_container(require_docker: None):
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


@pytest.fixture(scope="session")
def postgres_sync_url(postgres_container: PostgresContainer) -> str:
    return normalize_sync_sqlalchemy_url(postgres_container.get_connection_url())


@pytest.fixture(scope="session")
def migrated_sync_url(postgres_sync_url: str) -> str:
    run_alembic_upgrade(postgres_sync_url)
    return postgres_sync_url


@pytest.fixture(scope="session")
def sociacl_rls_role_ready(migrated_sync_url: str) -> None:
    """Create a role without BYPASSRLS so row-level security is enforced.

    The default Testcontainers ``test`` user is often a superuser, which bypasses
    RLS even when ``FORCE ROW LEVEL SECURITY`` is enabled. Tests that assert RLS
    must ``SET ROLE`` to this role after granting it ``SELECT`` on tenant tables.
    """
    eng = create_engine(migrated_sync_url)
    role = "sociacl_rls_tester"
    with eng.begin() as cx:
        cx.execute(
            text(
                f"""
                DO $$ BEGIN
                    CREATE ROLE {role} NOINHERIT NOBYPASSRLS;
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END $$;
                """
            )
        )
        cx.execute(text(f"GRANT SELECT ON sociacl_share_links TO {role}"))
        cx.execute(text(f"GRANT {role} TO CURRENT_USER"))


@pytest.fixture(scope="session")
def seed(migrated_sync_url: str) -> Seed:
    ta, tb = uuid.uuid4(), uuid.uuid4()
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :n, true)"),
            {"id": ta, "n": f"tenant-{ta.hex[:8]}"},
        )
        cx.execute(
            text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :n, true)"),
            {"id": tb, "n": f"tenant-{tb.hex[:8]}"},
        )
    return Seed(ta, tb)


@pytest.fixture
def _clean_acl_policies_tenant_a(migrated_sync_url: str, seed: Seed) -> None:
    """Clear tenant-A Casbin rows so RBAC (3-field ``p``) and ABAC (4-field ``p``) never mix in one load."""
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("DELETE FROM acl_casbin_rules WHERE tenant_id = :tid"),
            {"tid": seed.ta},
        )
        cx.execute(
            text("DELETE FROM sociacl_share_links WHERE tenant_id = :tid"),
            {"tid": seed.ta},
        )
        cx.execute(
            text("DELETE FROM sociacl_recovery_sessions WHERE tenant_id = :tid"),
            {"tid": seed.ta},
        )


@pytest.fixture
def event_sink() -> list:
    return []


@pytest.fixture
def app(event_sink: list, migrated_sync_url: str, monkeypatch: pytest.MonkeyPatch):
    db_url = migrated_sync_url
    if "+psycopg" in db_url:
        db_url = db_url.replace("postgresql+psycopg://", "postgresql://", 1)
    monkeypatch.setattr(api_config.settings, "database_url", db_url)
    monkeypatch.setattr(api_config.settings, "kafka_bootstrap_servers", None)
    monkeypatch.setattr(api_config.settings, "service_name", "acl-service-test")
    monkeypatch.setattr(api_config.settings, "acl_rate_limit_per_minute", 50_000)

    from acl_service.app import create_app

    return create_app(test_event_sink=event_sink)


@pytest.fixture
def auth_context(seed: Seed):
    sub = "11111111-1111-1111-1111-111111111111"

    async def _user() -> AuthMeResponse:
        return AuthMeResponse(
            sub=sub,
            email="actor@example.com",
            tenant_id=seed.ta,
            roles=[],
            scopes=[],
        )

    async def _tenant() -> uuid.UUID:
        return seed.ta

    return _user, _tenant, sub


@pytest.fixture
async def http_client(app, auth_context):
    _user, _tenant, _ = auth_context
    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_tenant] = _tenant
    import httpx
    from asgi_lifespan import LifespanManager

    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_tenant, None)


@pytest.fixture
def tenant_headers(seed: Seed) -> dict[str, str]:
    return {
        "Authorization": "Bearer test-token",
        "X-Tenant-ID": str(seed.ta),
    }
