from __future__ import annotations

import uuid
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclRecoverySession
from acl_service.domain.recovery_store import RecoverySession


def _set_guc(session: Session, tenant_id: uuid.UUID) -> None:
    session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


def create_or_get_session(
    sync_engine,
    tenant_id: uuid.UUID,
    *,
    idempotency_key: str,
    metadata: dict | None,
    ttl_minutes: int = 30,
) -> SociaclRecoverySession:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_minutes)
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        # Serialize same-key creates across processes without coupling the API to
        # PostgreSQL. Hash collisions only serialize unrelated requests; the
        # subsequent lookup still compares the full tenant and key.
        lock_key = int.from_bytes(hashlib.sha256(
            tenant_id.bytes + idempotency_key.encode("utf-8")
        ).digest()[:8], "big", signed=True)
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
        existing = session.scalars(
            select(SociaclRecoverySession).where(
                SociaclRecoverySession.tenant_id == tenant_id,
                SociaclRecoverySession.idempotency_key == idempotency_key,
            )
        ).first()
        if existing:
            return existing
        row = SociaclRecoverySession(
            tenant_id=tenant_id,
            state="pending",
            idempotency_key=idempotency_key,
            expires_at=exp,
            metadata_=metadata,
        )
        session.add(row)
        session.commit()
        _set_guc(session, tenant_id)
        session.refresh(row)
        return row


def transition_state(
    sync_engine,
    tenant_id: uuid.UUID,
    session_id: uuid.UUID,
    new_state: str,
) -> SociaclRecoverySession | None:
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        row = session.scalars(select(SociaclRecoverySession).where(
            SociaclRecoverySession.id == session_id,
            SociaclRecoverySession.tenant_id == tenant_id,
        ).with_for_update()).first()
        if row is None:
            return None
        row.state = new_state
        session.commit()
        _set_guc(session, tenant_id)
        session.refresh(row)
        return row


def _snapshot(row: SociaclRecoverySession) -> RecoverySession:
    return RecoverySession(row.id, row.state, row.idempotency_key, row.expires_at)


class PostgresRecoveryStore:
    """Keep session lifecycle, locking and RLS behind the recovery API."""

    def __init__(self, engine):
        self._engine = engine

    def create_or_get_session(self, tenant_id, *, idempotency_key, metadata, ttl_minutes=30):
        return _snapshot(create_or_get_session(self._engine, tenant_id,
            idempotency_key=idempotency_key, metadata=metadata, ttl_minutes=ttl_minutes))

    def transition_state(self, tenant_id, session_id, new_state):
        row = transition_state(self._engine, tenant_id, session_id, new_state)
        return _snapshot(row) if row is not None else None
