"""Per-request async DB session + RLS GUC from X-Tenant-ID."""

from __future__ import annotations

import uuid

from fastapi import Request
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware

from api.infrastructure.persistence.db_session import (
    get_session_maker,
    reset_db_session,
    set_db_session,
)


class AclServiceDbMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        maker = get_session_maker()
        async with maker() as session:
            token = set_db_session(session)
            try:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id', '', true)")
                )
                raw = request.headers.get("X-Tenant-ID")
                if raw:
                    try:
                        tid = uuid.UUID(str(raw))
                    except ValueError:
                        from starlette.responses import JSONResponse

                        return JSONResponse(
                            status_code=400,
                            content={"error": "Invalid X-Tenant-ID"},
                        )
                    await session.execute(
                        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                        {"tid": str(tid)},
                    )
                    request.state.tenant_id = tid
                else:
                    request.state.tenant_id = None
                response = await call_next(request)
                await session.commit()
                return response
            except Exception:
                await session.rollback()
                raise
            finally:
                reset_db_session(token)
