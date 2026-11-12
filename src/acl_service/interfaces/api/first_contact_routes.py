"""Public requests remain ciphertext and never confer identity or ACL authority."""
import asyncio
import base64

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from acl_service.infrastructure.first_contact_store import LaneCapacity, MAX_CIPHERTEXT, validate_lane

router = APIRouter(prefix="/api/v1/acl/sociacl/first-contact", tags=["SociACL"])
HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


def store_for(request: Request, lane: str):
    try:
        validate_lane(lane)
    except ValueError as exc:
        raise HTTPException(404, "Unknown route") from exc
    store = getattr(request.app.state, "first_contact_store", None)
    if store is None:
        raise HTTPException(503, "Lane storage unavailable")
    return store


@router.post("/{lane}/messages")
async def append_message(lane: str, request: Request):
    store = store_for(request, lane)
    if request.headers.get("content-type", "").lower() != "application/octet-stream":
        raise HTTPException(415, "Ciphertext requires application/octet-stream")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_CIPHERTEXT:
            raise HTTPException(413, "Ciphertext too large")
        body.extend(chunk)
    if len(body) < 94:
        raise HTTPException(400, "Ciphertext too small")
    try:
        digest = await asyncio.to_thread(store.append, lane, bytes(body))
    except LaneCapacity as exc:
        raise HTTPException(429, "Lane storage limit reached", headers={"Retry-After": "60"}) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(503, "Lane storage unavailable") from exc
    return JSONResponse({"id": digest}, headers=HEADERS)


@router.get("/{lane}/messages")
async def read_messages(lane: str, request: Request):
    store = store_for(request, lane)
    try:
        rows = await asyncio.to_thread(store.read, lane)
    except SQLAlchemyError as exc:
        raise HTTPException(503, "Lane storage unavailable") from exc
    return JSONResponse({"messages": [{"id": row["id"], "ciphertext": base64.b64encode(row["ciphertext"]).decode("ascii")}
                                     for row in rows]}, headers=HEADERS)
