from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclShareLink


def hash_share_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _set_guc(session: Session, tenant_id: uuid.UUID) -> None:
    session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


def lookup_share_by_token_hash(
    sync_engine,
    token_hash: str,
) -> SociaclShareLink | None:
    """Resolve share by hash across tenants (uses SECURITY DEFINER function)."""
    with Session(sync_engine) as session:
        row = session.execute(
            text("SELECT id, tenant_id FROM sociacl_share_lookup_by_hash(:h)"),
            {"h": token_hash},
        ).first()
        if row is None:
            return None
        sid, tid = row[0], row[1]
        _set_guc(session, tid)
        return session.get(SociaclShareLink, sid)


def create_share(
    sync_engine,
    *,
    tenant_id: uuid.UUID,
    resource_kind: str,
    resource_descriptor: dict,
    predicate_json: dict,
    mode: str,
    expires_at: datetime | None,
    uses_remaining: int | None,
    owner_user_id: uuid.UUID | None,
    group_id: uuid.UUID | None,
    created_by: str | None,
) -> tuple[SociaclShareLink, str]:
    raw = secrets.token_urlsafe(32)
    th = hash_share_token(raw)
    prefix = th[:8]
    row = SociaclShareLink(
        tenant_id=tenant_id,
        token_hash=th,
        token_prefix=prefix,
        owner_user_id=owner_user_id,
        group_id=group_id,
        resource_kind=resource_kind,
        resource_descriptor=resource_descriptor,
        predicate_json=predicate_json,
        mode=mode,
        expires_at=expires_at,
        uses_remaining=uses_remaining,
        created_by=created_by,
    )
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        session.add(row)
        session.commit()
        _set_guc(session, tenant_id)
        session.refresh(row)
        return row, raw


def list_shares(sync_engine, tenant_id: uuid.UUID) -> list[SociaclShareLink]:
    """Tenant-scoped share metadata. Token hash is never returned to callers."""
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        return list(
            session.scalars(
                select(SociaclShareLink)
                .where(SociaclShareLink.tenant_id == tenant_id)
                .order_by(SociaclShareLink.created_at.desc())
            ).all()
        )


def decrement_uses(
    sync_engine, tenant_id: uuid.UUID, share_id: uuid.UUID
) -> bool:
    """Decrement uses_remaining when finite; returns False if exhausted."""
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        obj = session.get(SociaclShareLink, share_id)
        if obj is None:
            return False
        if obj.uses_remaining is None:
            return True
        if obj.uses_remaining <= 0:
            return False
        obj.uses_remaining -= 1
        session.commit()
        return True
