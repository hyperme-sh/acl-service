from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy import create_engine

from api.common.exceptions import ForbiddenException, UnauthorizedException
from api.common.logging import configure_logging
from api.common.utils import get_logger
from api.core.config import settings
from api.infrastructure.messaging.tenant_event_publisher import (
    KafkaTenantEventPublisher,
    NoOpTenantEventPublisher,
    set_tenant_event_publisher,
)
from api.infrastructure.persistence.db_session import configure_session_maker
from api.interfaces.api_controllers.health_endpoint import router as health_router
from controlplane_db.session import normalize_database_url
from controlplane_events import AioKafkaEventProducer

from acl_service.infrastructure.db_url import sync_database_url
from acl_service.interfaces.api.routes import router as acl_router
from acl_service.interfaces.api.sociacl_routes import router as sociacl_router
from acl_service.middleware import AclServiceDbMiddleware

logger = get_logger(__name__)


def create_app(*, test_event_sink: list | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        engine = create_async_engine(normalize_database_url(settings.database_url))
        maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        configure_session_maker(maker)
        app.state.async_engine = engine
        sync_eng = create_engine(sync_database_url(settings.database_url), pool_pre_ping=True)
        app.state.sync_engine = sync_eng

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
        elif settings.kafka_bootstrap_servers:
            kafka_producer = AioKafkaEventProducer(
                settings.kafka_bootstrap_servers,
                client_id=f"{settings.service_name}-acl-events",
            )
            await kafka_producer.start()
            set_tenant_event_publisher(
                KafkaTenantEventPublisher(
                    kafka_producer,
                    settings.kafka_events_topic,
                    settings.service_name,
                )
            )
            app.state.kafka_producer = kafka_producer
        else:
            set_tenant_event_publisher(NoOpTenantEventPublisher())

        yield

        set_tenant_event_publisher(None)
        kp = getattr(app.state, "kafka_producer", None)
        if kp is not None:
            await kp.stop()
        sync_eng.dispose()
        await engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="Panopticon ACL Service",
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
    app.include_router(acl_router, prefix="/api/v1")
    app.include_router(sociacl_router, prefix="/api/v1")
    logger.info("ACL service: middleware + /api/v1 routes")
    return app


app = create_app()
