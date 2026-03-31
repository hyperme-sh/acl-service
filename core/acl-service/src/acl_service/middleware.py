"""Per-request async DB session + RLS GUC from X-Tenant-ID."""

from __future__ import annotations

import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from api.infrastructure.persistence.db_session import (
    get_session_maker,
    reset_db_session,
    set_db_session,
)
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc


class AclServiceDbMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        maker = get_session_maker()
        async with maker() as session:
            token = set_db_session(session)
            try:
                await set_current_tenant_id_guc(session, None)
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
                    await set_current_tenant_id_guc(session, tid)
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
