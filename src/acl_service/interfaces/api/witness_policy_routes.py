"""Public, read-only delivery of an already installed administrator-signed policy."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from acl_service.infrastructure.witness_policy_publication import PUBLIC_POLICY_PATH

router = APIRouter(tags=["SociACL"])
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.get(PUBLIC_POLICY_PATH, responses={404: {"description": "Disabled"},
                                         503: {"description": "Policy unavailable"}})
def witness_policy(request: Request) -> JSONResponse:
    publication = getattr(request.app.state, "witness_policy_publication", None)
    if publication is None:
        return JSONResponse({"error": "not-found"}, status_code=404, headers=NO_STORE)
    try:
        envelope = publication.export(request.app.state.witness_policy_reader)
    except Exception:
        # Fail closed on unavailable DB/files, expiry, signature or revision mismatch.
        # Do not return paths, SQL details, policy data or a stale cached response.
        return JSONResponse({"error": "witness-policy-unavailable"}, status_code=503, headers=NO_STORE)
    return JSONResponse(envelope, headers=NO_STORE)
