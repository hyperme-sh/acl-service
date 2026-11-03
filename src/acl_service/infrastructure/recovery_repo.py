from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclRecoverySession


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
        row = session.get(SociaclRecoverySession, session_id)
        if row is None:
            return None
        row.state = new_state
        session.commit()
        session.refresh(row)
        return row
