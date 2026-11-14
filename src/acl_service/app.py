from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections.abc import Mapping
from types import MappingProxyType
from uuid import UUID

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy import create_engine

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.config import settings
from api.infrastructure.persistence.db_session import configure_session_maker
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router
from controlplane_db.session import normalize_database_url

from api.infrastructure.tenant_user_rate_limiter import TenantUserRateLimiter

from acl_service.infrastructure.witness_policy_repo import PostgresWitnessPolicyReader
from acl_service.infrastructure.db_url import sync_database_url
from acl_service.infrastructure.policy_repo import PostgresPolicyStore
from acl_service.infrastructure.recovery_repo import PostgresRecoveryStore
from acl_service.infrastructure.membership_reader import PostgresMembershipReader
from acl_service.infrastructure.share_repo import PostgresShareStore
from acl_service.infrastructure.user_created_consumer import build_user_created_consumer
from acl_service.interfaces.api.routes import router as acl_router
from acl_service.interfaces.api.sociacl_routes import router as sociacl_router
from acl_service.middleware import AclServiceDbMiddleware
from acl_service.infrastructure.witness_policy_publication import load_publication
from acl_service.interfaces.api.witness_policy_routes import router as witness_policy_router

from acl_service.interfaces.api.statement_routes import StatementBinding, router as statement_router
from acl_service.interfaces.api.delegation_routes import router as delegation_router
from acl_service.interfaces.api.private_wrap_routes import PrivateWrapBinding, router as private_wrap_router
from acl_service.interfaces.api.signed_store_routes import SignedStoreBinding, router as signed_store_router
from acl_service.interfaces.api.contact_lane_routes import router as contact_lane_router
from acl_service.interfaces.api.first_contact_routes import router as first_contact_router
from acl_service.infrastructure.first_contact_store import PostgresFirstContactStore
from acl_service.infrastructure.contact_lane_store import PostgresContactLaneStore

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    service_name: str | None = None,
    signed_store_bindings: Mapping[tuple[UUID, str], SignedStoreBinding] | None = None,
    statement_bindings: Mapping[tuple[UUID, str, str], StatementBinding] | None = None,
    delegation_bindings: Mapping[tuple[UUID, str, str], StatementBinding] | None = None,
    private_wrap_bindings: Mapping[tuple[UUID, str], PrivateWrapBinding] | None = None,
    media_allocation_bindings: Mapping | None = None,
) -> FastAPI:
    if statement_bindings is None:
        from acl_service.infrastructure.statement_bindings import load_statement_bindings
        statement_bindings = load_statement_bindings()
    if delegation_bindings is None:
        from acl_service.infrastructure.delegation_bindings import load_delegation_bindings
        delegation_bindings = load_delegation_bindings()
    owns_allocation_clients = media_allocation_bindings is None
    if owns_allocation_clients:
        from acl_service.infrastructure.media_allocation_bindings import load_allocation_bindings
        media_allocation_bindings = load_allocation_bindings()
    owns_media_stores = private_wrap_bindings is None
    if owns_media_stores:
        from acl_service.infrastructure.media_bindings import load_media_bindings
        private_wrap_bindings = (load_media_bindings(allocation_bindings=media_allocation_bindings)
                                 if media_allocation_bindings else load_media_bindings())
    svc_name = service_name or settings.service_name
    from acl_service.lane_access_log import install_lane_log_filter
    install_lane_log_filter()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        app.state.witness_policy_publication = load_publication()
        engine = create_async_engine(normalize_database_url(settings.database_url))
        maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        configure_session_maker(maker)
        app.state.async_engine = engine
        sync_eng = create_engine(sync_database_url(settings.database_url), pool_pre_ping=True)
        app.state.sync_engine = sync_eng
        app.state.contact_lane_store = PostgresContactLaneStore(sync_eng)
        app.state.first_contact_store = PostgresFirstContactStore(sync_eng)
        app.state.policy_store = PostgresPolicyStore(sync_eng)
        app.state.recovery_store = PostgresRecoveryStore(sync_eng)
        app.state.membership_reader = PostgresMembershipReader(sync_eng)
        app.state.share_store = PostgresShareStore(sync_eng)
        app.state.witness_policy_reader = PostgresWitnessPolicyReader(sync_eng)
        app.state.rate_limiter = TenantUserRateLimiter(
            per_minute=settings.acl_rate_limit_per_minute,
        )

        if test_event_sink is not None:
            for store in (app.state.policy_store,app.state.share_store,app.state.recovery_store):
                store.event_sink=test_event_sink
        user_consumer=build_user_created_consumer(app.state.policy_store)
        await user_consumer.start()
        app.state.event_consumer=user_consumer

        try:
            yield
        finally:
            if owns_allocation_clients:
                clients = {id(binding.client): binding.client for binding in (media_allocation_bindings or {}).values()}
                for client in clients.values():
                    await client.close()
            if owns_media_stores:
                stores = {id(binding.store): binding.store for binding in (private_wrap_bindings or {}).values()}
                for store in stores.values():
                    await store.close()

        event_consumer = getattr(app.state, "event_consumer", None)
        if event_consumer is not None:
            await event_consumer.stop()
        sync_eng.dispose()
        await engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="spanopticon ACL Service",
        description="Casbin policies with tenant isolation (RLS) and SociACL-oriented ABAC.",
        version="0.1.0",
    )

    @app.exception_handler(UnauthorizedException)
    async def _unauthorized(_: Request, ex: UnauthorizedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": ex.message},
        )

    @app.exception_handler(ForbiddenException)
    async def _forbidden(_: Request, ex: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ex.message},
        )

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description or "",
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})[
            "BearerAuth"
        ] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Keycloak access token; X-Tenant-ID must match tenant claim",
        }
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    app.state.signed_store_bindings = (MappingProxyType(dict(signed_store_bindings))
                                       if signed_store_bindings is not None else None)
    app.include_router(signed_store_router, prefix="/api/v1")
    app.state.statement_bindings = MappingProxyType(dict(statement_bindings)) if statement_bindings is not None else None
    app.state.statement_slots = asyncio.Semaphore(2)
    app.include_router(statement_router, prefix="/api/v1")
    app.state.delegation_bindings = MappingProxyType(dict(delegation_bindings)) if delegation_bindings is not None else None
    # Both sources share the same bounded worker budget.
    app.state.delegation_slots = app.state.statement_slots
    app.include_router(delegation_router, prefix="/api/v1")
    app.state.private_wrap_bindings = MappingProxyType(dict(private_wrap_bindings)) if private_wrap_bindings is not None else None
    app.state.private_wrap_slots = asyncio.Semaphore(2)
    app.state.private_wrap_body_slots = {key: asyncio.Semaphore(1) for key in (private_wrap_bindings or {})}
    app.state.private_wrap_tenant_slots = {key[0]: asyncio.Semaphore(1) for key in (private_wrap_bindings or {})}
    app.include_router(private_wrap_router, prefix="/api/v1")
    from acl_service.interfaces.api.media_owner_routes import router as media_owner_router
    app.include_router(media_owner_router, prefix="/api/v1")
    app.state.media_allocation_bindings = MappingProxyType(dict(media_allocation_bindings)) if media_allocation_bindings is not None else None
    app.state.media_allocation_slots = asyncio.Semaphore(2)
    app.state.media_allocation_body_slots = {key: asyncio.Semaphore(1) for key in (media_allocation_bindings or {})}
    app.state.media_allocation_tenant_slots = {key[0]: asyncio.Semaphore(1) for key in (media_allocation_bindings or {})}
    from acl_service.interfaces.api.media_allocation_routes import router as media_allocation_router
    app.include_router(media_allocation_router, prefix='/api/v1')
    app.include_router(contact_lane_router)
    app.include_router(first_contact_router)
    app.add_middleware(AclServiceDbMiddleware)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    from acl_service.interfaces.api.events import router as events_router
    app.include_router(events_router)
    app.include_router(acl_router, prefix="/api/v1")
    from acl_service.startup_routes import router as startup_router
    app.include_router(startup_router, prefix="/api/v1")
    app.include_router(sociacl_router, prefix="/api/v1")
    app.include_router(witness_policy_router)
    add_optional_service_cors(app, env_var="ACL_SERVICE_CORS_ORIGINS")
    logger.info("ACL service: middleware + /api/v1 routes + optional CORS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
