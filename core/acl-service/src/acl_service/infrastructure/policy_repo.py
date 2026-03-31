from __future__ import annotations

import uuid

from sqlalchemy import and_, select, text
from sqlalchemy.orm import Session

from controlplane_db.models import AclCasbinRule


def _set_guc(session: Session, tenant_id: uuid.UUID) -> None:
    session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


def list_rules(sync_engine, tenant_id: uuid.UUID) -> list[AclCasbinRule]:
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        return list(
            session.scalars(
                select(AclCasbinRule)
                .where(AclCasbinRule.tenant_id == tenant_id)
                .order_by(AclCasbinRule.id)
            ).all()
        )


def add_rule(sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> AclCasbinRule:
    row = AclCasbinRule(tenant_id=tenant_id, ptype=ptype)
    for i, v in enumerate(rule):
        setattr(row, f"v{i}", v)
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        session.add(row)
        session.commit()
        session.refresh(row)
        return row


def delete_rule(sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> bool:
    conds = [
        AclCasbinRule.tenant_id == tenant_id,
        AclCasbinRule.ptype == ptype,
    ]
    for i, v in enumerate(rule):
        conds.append(getattr(AclCasbinRule, f"v{i}") == v)
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        obj = session.scalars(select(AclCasbinRule).where(and_(*conds))).one_or_none()
        if obj is None:
            return False
        session.delete(obj)
        session.commit()
        return True
