"""Durable policy lifecycle for already-authenticated operator updates.

No network input is authenticated here. Never pass caller-selected policy to
install_verified_policy. All workers must use this same deployment-wide row.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from collections.abc import Sequence

from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclWitnessPolicy
from acl_service.infrastructure.witness_signer import (
    MAX_INTEGER, WitnessKey, WitnessRejected, WitnessSigner, public_jwks,
)


@dataclass(frozen=True)
class PolicySnapshot:
    revision: int
    jwks: dict


def _snapshot(row):
    return PolicySnapshot(row.revision, deepcopy(row.jwks))


def read_policy(engine) -> PolicySnapshot | None:
    with Session(engine) as session:
        row = session.get(SociaclWitnessPolicy, 1)
        return _snapshot(row) if row else None


def install_verified_policy(engine, revision: int, keys: Sequence[WitnessKey]) -> PolicySnapshot:
    """Atomically install trusted policy, preserving all retired/removed identities.

    Identical same-revision retries are idempotent. Different same-revision
    documents, older revisions, widened windows and resurrected keys fail closed.
    Omission permanently removes trust, unlike ordinary time-based retirement.
    """
    if type(revision) is not int or not 1 <= revision <= MAX_INTEGER:
        raise WitnessRejected()
    jwks = public_jwks(keys)
    jwks["keys"].sort(key=lambda key: key["kid"])
    with Session(engine) as session, session.begin():
        session.execute(insert(SociaclWitnessPolicy).values(id=1).on_conflict_do_nothing(index_elements=["id"]))
        row = session.scalars(select(SociaclWitnessPolicy).where(SociaclWitnessPolicy.id == 1).with_for_update()).one()
        if revision < row.revision or (revision == row.revision and jwks != row.jwks):
            raise WitnessRejected()
        if revision == row.revision:
            return _snapshot(row)
        history = deepcopy(row.history)
        material = {(value["jwk"]["x"], value["jwk"]["y"]): kid for kid, value in history.items()}
        present = set()
        for key in jwks["keys"]:
            kid = key["kid"]
            present.add(kid)
            identity = (key["x"], key["y"])
            old = history.get(kid)
            if old:
                previous = old["jwk"]
                if (old["removed"] or identity != (previous["x"], previous["y"])
                        or key["notBefore"] < previous["notBefore"]
                        or key["notAfter"] > previous["notAfter"]):
                    raise WitnessRejected()
            elif identity in material:
                raise WitnessRejected()
            history[kid] = {"jwk": key, "removed": False}
        for kid in history.keys() - present:
            history[kid]["removed"] = True
        row.revision, row.jwks, row.history = revision, jwks, history
        result = _snapshot(row)
    return result


def sign_with_policy(engine, kid: str, private_key, claims, *, issued_at: int, lifetime: int = 900) -> str:
    """Sign verified claims under current durable policy, serialized with updates.

    Same authorization obligations as WitnessSigner.sign_verified. No policy/key
    metadata may be cached across calls. Returning a token does not grant access.
    """
    with Session(engine) as session, session.begin():
        row = session.scalars(select(SociaclWitnessPolicy).where(SociaclWitnessPolicy.id == 1).with_for_update()).one_or_none()
        if row is None:
            raise WitnessRejected()
        jwk = next((key for key in row.jwks["keys"] if key["kid"] == kid), None)
        if jwk is None:
            raise WitnessRejected()
        def coordinate(value):
            return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")
        public = ec.EllipticCurvePublicNumbers(coordinate(jwk["x"]), coordinate(jwk["y"]), ec.SECP256R1()).public_key()
        key = WitnessKey(kid, jwk["notBefore"], jwk["notAfter"], public)
        token = WitnessSigner(key, private_key).sign_verified(claims, issued_at=issued_at, lifetime=lifetime)
    return token
