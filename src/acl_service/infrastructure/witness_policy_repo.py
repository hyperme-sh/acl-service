"""Durable policy lifecycle for already-authenticated operator updates.

No network input is authenticated here. Never pass caller-selected policy to
install_verified_policy. All workers must use this same deployment-wide row.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from collections.abc import Callable, Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclWitnessPolicy
from acl_service.domain.witness_policy_reader import PolicySnapshot, PolicyHistorySnapshot
from acl_service.infrastructure.witness_signer import (
    MAX_INTEGER, WitnessKey, WitnessRejected, public_jwks,
)


class PostgresWitnessPolicyReader:
    def __init__(self, engine):
        self._engine = engine

    @contextmanager
    def locked_policy(self):
        with Session(self._engine) as session, session.begin():
            row = session.scalars(select(SociaclWitnessPolicy)
                                  .where(SociaclWitnessPolicy.id == 1)
                                  .with_for_update(read=True)).one_or_none()
            yield _snapshot(row) if row is not None else None


class PostgresWitnessSigningPolicyReader:
    """Preserve exclusive signing serialization against all policy operations."""
    def __init__(self, engine):
        self._engine = engine

    @contextmanager
    def locked_policy(self):
        with Session(self._engine) as session, session.begin():
            row = session.scalars(select(SociaclWitnessPolicy)
                                  .where(SociaclWitnessPolicy.id == 1)
                                  .with_for_update()).one_or_none()
            yield _snapshot(row) if row is not None else None


class PostgresWitnessPolicyHistoryReader:
    def __init__(self, engine):
        self._engine = engine

    @contextmanager
    def locked_history(self):
        with Session(self._engine) as session, session.begin():
            row = session.scalars(select(SociaclWitnessPolicy)
                                  .where(SociaclWitnessPolicy.id == 1)
                                  .with_for_update(read=True)).one_or_none()
            yield (PolicyHistorySnapshot(row.revision, deepcopy(row.jwks), deepcopy(row.history))
                   if row is not None else None)


class PostgresWitnessPolicyWriter:
    def __init__(self, engine):
        self._engine = engine

    def install_verified(self, revision, keys, *, check_authorization):
        return install_verified_policy(
            self._engine, revision, keys, check_authorization=check_authorization,
        )


def _snapshot(row):
    return PolicySnapshot(row.revision, deepcopy(row.jwks))


def read_policy(engine) -> PolicySnapshot | None:
    with Session(engine) as session:
        row = session.get(SociaclWitnessPolicy, 1)
        return _snapshot(row) if row else None


def install_verified_policy(engine, revision: int, keys: Sequence[WitnessKey],
                            *, check_authorization: Callable[[], None] | None = None) -> PolicySnapshot:
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
        if check_authorization is not None:
            check_authorization()
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
    """Compatibility entry point; new callers inject a signing policy reader."""
    from acl_service.infrastructure.witness_policy_signing import sign_with_policy as sign
    return sign(PostgresWitnessSigningPolicyReader(engine), kid, private_key, claims,
                issued_at=issued_at, lifetime=lifetime)
