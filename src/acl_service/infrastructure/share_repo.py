from __future__ import annotations

from copy import deepcopy
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclShareLink
from acl_service.domain.share_store import ShareRecord, hash_share_token


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
    """Reserve an active use atomically; never acknowledge exhausted/foreign shares."""
    with Session(sync_engine) as session, session.begin():
        _set_guc(session, tenant_id)
        obj = session.scalars(select(SociaclShareLink).where(
            SociaclShareLink.id == share_id,
            SociaclShareLink.tenant_id == tenant_id,
        ).with_for_update()).first()
        if obj is None or obj.revoked_at is not None:
            return False
        # Evaluate the clock after acquiring the lock, not before waiting for it.
        if obj.expires_at is not None and obj.expires_at <= datetime.now(timezone.utc):
            return False
        if obj.uses_remaining is not None:
            if obj.uses_remaining <= 0:
                return False
            obj.uses_remaining -= 1
    return True


def _snapshot(row: SociaclShareLink) -> ShareRecord:
    return ShareRecord(**{name: deepcopy(getattr(row, name))
                          for name in ShareRecord.__dataclass_fields__})


class PostgresShareStore:
    def __init__(self, engine):
        self._engine = engine

    def create_share(self, **kwargs):
        row, token = create_share(self._engine, **kwargs)
        return _snapshot(row), token

    def list_shares(self, tenant_id):
        return [_snapshot(row) for row in list_shares(self._engine, tenant_id)]

    def lookup_share_by_token_hash(self, token_hash):
        row = lookup_share_by_token_hash(self._engine, token_hash)
        return _snapshot(row) if row is not None else None

    def decrement_uses(self, tenant_id, share_id):
        return decrement_uses(self._engine, tenant_id, share_id)
