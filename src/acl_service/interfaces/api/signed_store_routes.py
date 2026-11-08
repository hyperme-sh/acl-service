"""Tenant-authenticated transport for provisioned SociACL ciphertext writers."""
import asyncio
import json
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from fastapi.responses import JSONResponse

from auth_service.schemas import AuthMeResponse
from fastapi import APIRouter, Depends, HTTPException, Request

from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.domain.keyring_store import StoreKind, StoreRejected

router = APIRouter(prefix="/acl/sociacl/keyring", tags=["SociACL"])
# Covers a maximum hex-encoded recovery envelope or delivered wrap plus metadata.
MAX_OPERATION_BYTES = 2 * 1024 * 1024


class SignedWriter(Protocol):
    def read_store_row(self, principal: str, kind: StoreKind, target: str) -> dict: ...

    def apply_store_operation(self, principal: str, kind: StoreKind, operation: dict) -> int: ...


@dataclass(frozen=True)
class SignedStoreBinding:
    principal: str
    writer: SignedWriter


def _unique_fields(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate field")
    return obj


def _invalid_constant(value):
    raise ValueError("non-finite number")


def _binding(request, tenant, user):
    bindings = request.app.state.signed_store_bindings
    if bindings is None:
        raise HTTPException(503, "Signed storage is unavailable")
    binding = bindings.get((tenant, user.sub))
    if binding is None:
        raise HTTPException(403, "No signed storage binding")
    if not request.app.state.rate_limiter.allow(tenant, user.sub):
        raise HTTPException(429, "Rate limit exceeded")
    return binding


@router.post("/{kind}/operations", openapi_extra={
    "security": [{"BearerAuth": []}],
    "parameters": [{"name": "X-Tenant-ID", "in": "header", "required": True,
                    "schema": {"type": "string", "format": "uuid"}}],
    "requestBody": {"required": True, "content": {"application/json": {"schema": {
        "type": "object", "required": ["action", "signature"],
        "properties": {"action": {"enum": ["put", "commit", "delete"]},
                       "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}},
    }}}},
})
async def apply_signed_operation(
    kind: StoreKind, request: Request,
    tenant: UUID = Depends(require_matched_tenant),
    user: AuthMeResponse = Depends(get_current_user),
) -> dict[str, int]:
    binding = _binding(request, tenant, user)
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Expected application/json")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_OPERATION_BYTES:
            raise HTTPException(413, "Signed operation too large")
        data.extend(chunk)
    try:
        operation = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields,
                               parse_constant=_invalid_constant)
        if not isinstance(operation, dict):
            raise ValueError("expected an object")
        # Reject exponent overflow as well as literal non-finite values before dispatch.
        json.dumps(operation, allow_nan=False)
    except (ValueError, RecursionError) as exc:
        raise HTTPException(400, "Invalid signed operation JSON") from exc

    try:
        generation = await asyncio.to_thread(
            binding.writer.apply_store_operation, binding.principal, kind, operation
        )
    except AdmissionRejected as exc:
        raise HTTPException(403, "Signed operation rejected") from exc
    except (HistoryConflict, StoreRejected) as exc:
        raise HTTPException(409, "Store state changed; reread before signing again") from exc
    return {"generation": generation}


@router.get("/{kind}/rows/{target}")
async def read_signed_row(
    kind: StoreKind, target: str, request: Request,
    tenant: UUID = Depends(require_matched_tenant),
    user: AuthMeResponse = Depends(get_current_user),
):
    binding = _binding(request, tenant, user)
    try:
        result = await asyncio.to_thread(binding.writer.read_store_row, binding.principal, kind, target)
    except AdmissionRejected as exc:
        raise HTTPException(403, "Store read rejected") from exc
    except (HistoryConflict, StoreRejected) as exc:
        raise HTTPException(409, "Store state changed; reread before signing again") from exc
    return JSONResponse(result, headers={"Cache-Control": "no-store"})
