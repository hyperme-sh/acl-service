from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy import create_engine

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.config import settings
from api.infrastructure.messaging.tenant_event_publisher import (
    install_tenant_event_publisher,
    set_tenant_event_publisher,
    shutdown_tenant_event_publisher,
)
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

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    service_name: str | None = None,
) -> FastAPI:
    svc_name = service_name or settings.service_name

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
        app.state.policy_store = PostgresPolicyStore(sync_eng)
        app.state.recovery_store = PostgresRecoveryStore(sync_eng)
        app.state.membership_reader = PostgresMembershipReader(sync_eng)
        app.state.share_store = PostgresShareStore(sync_eng)
        app.state.witness_policy_reader = PostgresWitnessPolicyReader(sync_eng)
        app.state.rate_limiter = TenantUserRateLimiter(
            per_minute=settings.acl_rate_limit_per_minute,
        )

        if test_event_sink is not None:

            class _ListSink:
                async def publish(
                    self,
                    *,
                    tenant_id,
                    event_type: str,
                    payload: dict,
                    correlation_id: str | None = None,
                ) -> None:
                    test_event_sink.append(
                        {
                            "tenant_id": tenant_id,
                            "event_type": event_type,
                            "payload": payload,
                            "correlation_id": correlation_id,
                        }
                    )

            set_tenant_event_publisher(_ListSink())
        else:
            await install_tenant_event_publisher(service_name=svc_name)
            user_consumer = build_user_created_consumer(app.state.policy_store, settings.database_url)
            await user_consumer.start()
            app.state.event_consumer = user_consumer

        yield

        event_consumer = getattr(app.state, "event_consumer", None)
        if event_consumer is not None:
            await event_consumer.stop()
        await shutdown_tenant_event_publisher()
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

    app.add_middleware(AclServiceDbMiddleware)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    app.include_router(acl_router, prefix="/api/v1")
    app.include_router(sociacl_router, prefix="/api/v1")
    app.include_router(witness_policy_router)
    add_optional_service_cors(app, env_var="ACL_SERVICE_CORS_ORIGINS")
    logger.info("ACL service: middleware + /api/v1 routes + optional CORS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
