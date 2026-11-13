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


from acl_service.infrastructure.witness_policy_publication import PUBLIC_POLICY_PATH
from acl_service.infrastructure.contact_lane_store import is_contact_lane_path


class AclServiceDbMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # This global public registry uses its own shared policy lock and no tenant
        # session. Keep the exception exact: all existing tenant routes are unchanged.
        if (request.method == "GET" and request.url.path == PUBLIC_POLICY_PATH) or is_contact_lane_path(request.url.path, request.method):
            return await call_next(request)
        if request.method == 'POST' and request.url.path == '/internal/events':
            return await call_next(request)
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
                if response.status_code >= 400:
                    await session.rollback()
                else:
                    await session.commit()
                return response
            except Exception:
                await session.rollback()
                raise
            finally:
                reset_db_session(token)
