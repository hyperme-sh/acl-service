"""Internal complete policy snapshot boundary for a future management issuer.

History is trusted database state, not authenticated by the current policy's
signature. No public endpoint, management authorization or rollback anchor is
provided here. Keep checkpoint signing inside the context and release the result
only after successful context exit.
"""
from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclWitnessPolicy
from acl_service.infrastructure.witness_policy_ingest import _parse_jwks, verify_policy
from acl_service.infrastructure.witness_signer import WitnessRejected, public_jwks

MAX_HISTORY = 1024
MAX_STATE_BYTES = 2097152


@dataclass(frozen=True)
class CompletePolicySnapshot:
    """Immutable exact JSON strings; a snapshot is not a freshness credential."""
    state_json: str
    policy_json: str
    expires_at: int


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _state(row, root_key, audience, verified) -> str:
    try:
        if (not isinstance(audience, str) or not 1 <= len(audience.encode("utf-8")) <= 1024
                or not isinstance(row.history, dict) or len(row.history) > MAX_HISTORY):
            raise WitnessRejected()
        current = public_jwks(_parse_jwks(row.jwks, root_key))
        expected = public_jwks(verified.keys)
        order = lambda key: key["kid"].encode("utf-8")
        current["keys"].sort(key=order)
        expected["keys"].sort(key=order)
        if row.revision != verified.revision or current != expected:
            raise WitnessRejected()
        history = []
        for kid, entry in row.history.items():
            if (not isinstance(entry, dict) or set(entry) != {"jwk", "removed"}
                    or type(entry["removed"]) is not bool or not isinstance(entry["jwk"], dict)
                    or entry["jwk"].get("kid") != kid):
                raise WitnessRejected()
            history.append(entry)
        # Validate removed keys too: material reuse, malformed points, old windows
        # and administrative-root reuse must never enter a signed checkpoint.
        _parse_jwks({"keys": [entry["jwk"] for entry in history]}, root_key)
        live = sorted((entry["jwk"] for entry in history if not entry["removed"]), key=order)
        if live != current["keys"]:
            raise WitnessRejected()
        history.sort(key=lambda entry: order(entry["jwk"]))
        point = root_key.public_numbers()
        root = _b64(point.x.to_bytes(32, "big")) + "." + _b64(point.y.to_bytes(32, "big"))
        result = _json({"type": "sociacl-witness-policy-state-v1", "root": root,
                        "audience": audience, "revision": verified.revision,
                        "jwks": current, "history": history})
        if len(result.encode("utf-8")) > MAX_STATE_BYTES:
            raise WitnessRejected()
        return result
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise WitnessRejected() from None


@contextmanager
def locked_complete_policy_snapshot(engine, payload: bytes, signature: bytes, root_key,
                                    audience: str) -> Iterator[CompletePolicySnapshot]:
    """Pair exact live signed policy with complete history under one shared lock.

    This uses the same singleton/serialization boundary as policy installation.
    Reject absent or inconsistent history; never reconstruct it from active JWKS.
    The future issuer must additionally authorize the client, reconcile protected
    management continuity/root epoch, bind a one-use challenge and sign with its
    independent management authority. It must not publish before context exit.
    """
    verified = verify_policy(payload, signature, root_key, audience)
    with Session(engine) as session, session.begin():
        row = session.scalars(select(SociaclWitnessPolicy)
                              .where(SociaclWitnessPolicy.id == 1)
                              .with_for_update(read=True)).one_or_none()
        verified.check_current()
        if row is None:
            raise WitnessRejected()
        state = _state(row, root_key, audience, verified)
        policy = _json({"type": "sociacl-witness-policy-envelope-v1",
                        "payload": _b64(payload), "signature": _b64(signature)})
        verified.check_current()
        yield CompletePolicySnapshot(state, policy, verified.expires_at)
        # A slow signer/consumer must discard its result if the policy expires.
        verified.check_current()
