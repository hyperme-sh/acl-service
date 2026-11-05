"""Service-owned recovery workflow storage; not proof verification or key recovery.

Implementations commit before returning, isolate every operation by tenant, and
serialize creates for each (tenant, idempotency key). Retrying creation returns
the existing snapshot without resetting its state, expiry or metadata. Storage
errors propagate. No SQL, ORM rows or transport types cross this interface.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class RecoverySession:
    id: UUID
    state: str
    idempotency_key: str
    expires_at: datetime


class RecoveryStore(Protocol):
    def create_or_get_session(
        self, tenant_id: UUID, *, idempotency_key: str,
        metadata: dict | None, ttl_minutes: int = 30,
    ) -> RecoverySession: ...

    def transition_state(
        self, tenant_id: UUID, session_id: UUID, new_state: str,
    ) -> RecoverySession | None: ...
