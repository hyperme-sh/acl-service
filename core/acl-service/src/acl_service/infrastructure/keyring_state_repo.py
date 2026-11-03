"""Durable storage primitive, not a SociACL verifier or HTTP authorization gate.

Only a trusted adapter may call this after package verification. It must validate
canonical principals, fresh complete history, store signatures, predecessor hashes,
and envelope semantics. Payloads serialize ciphertext rows, never keyring plaintext.
One PostgreSQL row lock serializes both stores for a principal across processes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclKeyringState

MAX_GENERATION = 9_007_199_254_740_991
StoreKind = Literal["recovery", "wraps"]


class StoreRejected(ValueError):
    def __init__(self) -> None:
        super().__init__("store-rejected")


@dataclass(frozen=True)
class KeyringState:
    head_floor: int
    recovery_generation: int
    wrap_generation: int
    recovery: bytes
    wraps: bytes


def _snapshot(row: SociaclKeyringState) -> KeyringState:
    return KeyringState(row.head_floor, row.recovery_generation,
                        row.wrap_generation, bytes(row.recovery), bytes(row.wraps))


def _integer(value: int) -> None:
    if type(value) is not int or not 0 <= value <= MAX_GENERATION:
        raise StoreRejected()


def _locked(session: Session, principal: str) -> SociaclKeyringState:
    # Concurrent first writes contend on the same PK, then the same row lock.
    session.execute(insert(SociaclKeyringState).values(principal=principal)
                    .on_conflict_do_nothing(index_elements=["principal"]))
    return session.scalars(select(SociaclKeyringState)
                           .where(SociaclKeyringState.principal == principal)
                           .with_for_update()).one()


def read_state(engine, principal: str) -> KeyringState | None:
    """Read one committed snapshot. Absence is not authority to create an account."""
    with Session(engine) as session:
        row = session.get(SociaclKeyringState, principal)
        return _snapshot(row) if row else None


def observe_verified_head(engine, principal: str, head: int) -> KeyringState:
    """Persist an authenticated resolver observation before returning it."""
    _integer(head)
    with Session(engine) as session, session.begin():
        row = _locked(session, principal)
        if head < row.head_floor:
            raise StoreRejected()
        row.head_floor = head
        result = _snapshot(row)
    return result


def compare_and_swap_verified(
    engine, principal: str, *, head: int, kind: StoreKind,
    expected_generation: int, payload: bytes,
) -> KeyringState:
    """Commit a verified transition; conflict requires re-read AND re-sign.

    The caller must have verified this exact payload and expected generation.
    No automatic retry: an ambiguous commit requires reading durable state.
    Empty payload deletes ciphertext, not the floor or generation tombstone.
    A stale generation still commits a newly verified floor observation.
    """
    _integer(head)
    _integer(expected_generation)
    if kind not in ("recovery", "wraps") or not isinstance(payload, bytes):
        raise StoreRejected()
    rejected = False
    with Session(engine) as session, session.begin():
        row = _locked(session, principal)
        if head < row.head_floor:
            raise StoreRejected()
        row.head_floor = head
        field = "recovery_generation" if kind == "recovery" else "wrap_generation"
        generation = getattr(row, field)
        if generation != expected_generation or generation == MAX_GENERATION:
            rejected = True
        else:
            setattr(row, kind, payload)
            setattr(row, field, generation + 1)
        result = _snapshot(row)
    # Raise after the transaction so a rejected write cannot roll back its floor.
    if rejected:
        raise StoreRejected()
    return result
