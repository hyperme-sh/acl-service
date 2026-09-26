from __future__ import annotations

import uuid

from sqlalchemy import and_, select, text
from sqlalchemy.exc import IntegrityError
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


def _rule_match(ptype: str, rule: list[str]) -> list:
    conds = [AclCasbinRule.ptype == ptype]
    for i in range(6):
        column = getattr(AclCasbinRule, f"v{i}")
        if i < len(rule):
            conds.append(column == rule[i])
        else:
            conds.append(column.is_(None))
    return conds


def _find_rule(session: Session, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> AclCasbinRule | None:
    return session.scalars(
        select(AclCasbinRule).where(
            and_(AclCasbinRule.tenant_id == tenant_id, *_rule_match(ptype, rule))
        )
    ).one_or_none()


def add_rule_if_absent(
    sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]
) -> bool:
    """Insert the rule once. False means it already existed (redelivery)."""

    row = AclCasbinRule(tenant_id=tenant_id, ptype=ptype)
    for i, value in enumerate(rule):
        setattr(row, f"v{i}", value)
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        existing = _find_rule(session, tenant_id, ptype, rule)
        if existing is not None:
            return False
        session.add(row)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            return False
        return True


def add_rule(sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> AclCasbinRule:
    row = AclCasbinRule(tenant_id=tenant_id, ptype=ptype)
    for i, v in enumerate(rule):
        setattr(row, f"v{i}", v)
    with Session(sync_engine) as session:
        _set_guc(session, tenant_id)
        existing = _find_rule(session, tenant_id, ptype, rule)
        if existing is not None:
            return existing
        session.add(row)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            _set_guc(session, tenant_id)
            found = _find_rule(session, tenant_id, ptype, rule)
            if found is None:
                raise
            return found
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
