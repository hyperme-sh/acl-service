"""Authenticated transport for explicitly provisioned signed graph sources."""
import asyncio
import json
import threading
from dataclasses import dataclass
from typing import Callable, Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.signed_store_routes import _unique_fields, _invalid_constant

router = APIRouter(prefix="/acl/sociacl/statements", tags=["SociACL"])

class Source(Protocol):
    tenant: str
    production_ready: bool
    def read(self, scope, at, cancel): ...
    def append(self, scope, at, fence, rows, cancel): ...
    def append_forum_update(self, scope, at, fence, rows, update, *, authorize_commit, cancel): ...

@dataclass(frozen=True)
class StatementBinding:
    scope: str
    source: Source
    forum_commit: Callable[[dict], None] | None = None

NATIVE_VAULT_SCOPE = "s3rch-native-vault"
NATIVE_VAULT_READ = "acl:vault:statements:read"

@router.post("/{scope}/{operation}")
async def statement_operation(scope: str, operation: str, request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    return await graph_operation(scope, operation, request, tenant, user,
                                 namespace="statement", permission_prefix="acl:statements:")


async def graph_operation(scope, operation, request, tenant, user, *, namespace, permission_prefix):
    bindings = getattr(request.app.state, namespace + "_bindings")
    if bindings is None: raise HTTPException(503, "Statement source unavailable")
    binding = bindings.get((tenant, user.sub, scope))
    if binding is None or binding.scope != scope or binding.source.tenant != str(tenant):
        raise HTTPException(403, "No statement source binding")
    if not binding.source.production_ready: raise HTTPException(503, "Statement source unavailable")
    forum_update = namespace == "statement" and operation == "forum-update"
    if forum_update and binding.forum_commit is None:
        raise HTTPException(503, "Forum commit authority unavailable")
    if operation not in ("snapshot", "append") and not forum_update: raise HTTPException(404, "Unknown operation")
    permission = permission_prefix + ("read" if operation == "snapshot" else "write")
    vault_reader = (namespace == "statement" and scope == NATIVE_VAULT_SCOPE
                    and operation == "snapshot" and NATIVE_VAULT_READ in user.scopes)
    if permission not in user.scopes and not vault_reader:
        raise HTTPException(403, "Statement scope required")
    if not request.app.state.rate_limiter.allow(tenant, user.sub): raise HTTPException(429, "Rate limit exceeded")
    slots = getattr(request.app.state, namespace + "_slots")
    if slots.locked(): raise HTTPException(429, "Statement source busy")
    await slots.acquire()
    stopped = threading.Event()
    work = None
    def guard():
        if stopped.is_set(): raise HistoryConflict("request expired")
    try:
        async with asyncio.timeout(1.5):
            if request.headers.get("content-type", "").split(";")[0] != "application/json" or request.headers.get("content-encoding", "identity") != "identity":
                raise HTTPException(415, "Expected uncompressed JSON")
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > (104000 if forum_update else 70000): raise HTTPException(413, "Request too large")
                data.extend(chunk)
            try:
                body = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
                keys = {"evaluatedAt"} if operation == "snapshot" else {"evaluatedAt", "fence", "rows"}
                if forum_update:
                    keys.add("update")
                if not isinstance(body, dict) or set(body) != keys or type(body["evaluatedAt"]) is not int:
                    raise ValueError()
                json.dumps(body, allow_nan=False)
            except (ValueError, RecursionError) as exc: raise HTTPException(400, "Invalid request") from exc
            if operation == "snapshot":
                work = asyncio.create_task(asyncio.to_thread(binding.source.read, scope, body["evaluatedAt"], guard))
                result = await asyncio.shield(work)
            elif forum_update:
                work = asyncio.create_task(asyncio.to_thread(binding.source.append_forum_update,
                    scope, body["evaluatedAt"], body["fence"], body["rows"], body["update"],
                    authorize_commit=binding.forum_commit, cancel=guard))
                result = {"ok": await asyncio.shield(work)}
            else:
                work = asyncio.create_task(asyncio.to_thread(binding.source.append, scope, body["evaluatedAt"], body["fence"], body["rows"], guard))
                result = {"ok": await asyncio.shield(work)}
            return JSONResponse(result, headers={"Cache-Control": "private, no-store"})
    except HistoryConflict as exc: raise HTTPException(409, "Statement source changed") from exc
    except AdmissionRejected as exc: raise HTTPException(403, "Statement source rejected") from exc
    except TimeoutError as exc: raise HTTPException(503, "Statement source timed out") from exc
    finally:
        stopped.set()
        if work is not None and not work.done():
            # Timeout cannot release a backend slot while its thread still runs.
            def finished(task):
                if not task.cancelled(): task.exception()
                slots.release()
            work.add_done_callback(finished)
        else: slots.release()
