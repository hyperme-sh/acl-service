from __future__ import annotations

import uuid

from sqlalchemy import and_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from acl_service.infrastructure.atomic import store_session

from controlplane_db.models import AclCasbinRule
from acl_service.domain.policy_store import PolicyRecord


def _set_guc(session: Session, tenant_id: uuid.UUID) -> None:
    session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


def list_rules(sync_engine, tenant_id: uuid.UUID) -> list[AclCasbinRule]:
    with store_session(sync_engine) as session:
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


def _find_rule(
    session: Session, tenant_id: uuid.UUID, ptype: str, rule: list[str]
) -> AclCasbinRule | None:
    """Lowest id if duplicates remain. ``one_or_none`` raises on more than one row."""

    return session.scalars(
        select(AclCasbinRule)
        .where(and_(AclCasbinRule.tenant_id == tenant_id, *_rule_match(ptype, rule)))
        .order_by(AclCasbinRule.id)
        .limit(1)
    ).first()


def add_rule_if_absent(
    sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]
) -> bool:
    """Insert the rule once. False means it already existed (redelivery)."""

    row = AclCasbinRule(tenant_id=tenant_id, ptype=ptype)
    for i, value in enumerate(rule):
        setattr(row, f"v{i}", value)
    with store_session(sync_engine) as session:
        _set_guc(session, tenant_id)
        existing = _find_rule(session, tenant_id, ptype, rule)
        if existing is not None:
            return False
        session.add(row)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            _set_guc(session, tenant_id)
            if _find_rule(session, tenant_id, ptype, rule) is None:
                raise
            return False
        return True


def add_rule(sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> AclCasbinRule:
    row = AclCasbinRule(tenant_id=tenant_id, ptype=ptype)
    for i, v in enumerate(rule):
        setattr(row, f"v{i}", v)
    with store_session(sync_engine) as session:
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
        _set_guc(session, tenant_id)
        session.refresh(row)
        return row


def delete_rule(sync_engine, tenant_id: uuid.UUID, ptype: str, rule: list[str]) -> bool:
    conds = [AclCasbinRule.tenant_id == tenant_id, *_rule_match(ptype, rule)]
    with store_session(sync_engine) as session:
        _set_guc(session, tenant_id)
        obj = session.scalars(
            select(AclCasbinRule).where(and_(*conds)).order_by(AclCasbinRule.id).limit(1)
        ).first()
        if obj is None:
            return False
        session.delete(obj)
        session.commit()
        return True


def _record(row: AclCasbinRule) -> PolicyRecord:
    return PolicyRecord(row.id, row.ptype, *(getattr(row, f"v{i}") for i in range(6)))


class PostgresPolicyStore:
    """Own SQL sessions and return detached, backend-neutral records."""

    def __init__(self, engine):
        self._engine = engine

    def list_rules(self, tenant_id):
        return [_record(row) for row in list_rules(self._engine, tenant_id)]

    def add_rule(self, tenant_id, ptype, rule):
        return _record(add_rule(self._engine, tenant_id, ptype, rule))

    def add_rule_if_absent(self, tenant_id, ptype, rule):
        return add_rule_if_absent(self._engine, tenant_id, ptype, rule)

    def delete_rule(self, tenant_id, ptype, rule):
        return delete_rule(self._engine, tenant_id, ptype, rule)


    def reconcile_startup(self, config, person):
        """Commit the binding and all grants together under a tenant lock."""
        from acl_service.startup_identity import plan, desired
        tenant = uuid.UUID(config['owner']['tenant_id'])
        with store_session(self._engine) as session, session.begin():
            _set_guc(session,tenant)
            session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                            {'key':'startup-acl:'+str(tenant)})
            rows=list(session.scalars(select(AclCasbinRule).where(AclCasbinRule.tenant_id==tenant)).all())
            additions=plan(config,person,[_record(row) for row in rows])
            for ptype,rule in additions:
                row=AclCasbinRule(tenant_id=tenant,ptype=ptype)
                for index,value in enumerate(rule):setattr(row,'v'+str(index),value)
                session.add(row)
            return {'status':'reconciled','mapping_sha256':config and person['mapping_sha256'],
                    'person_id':person['person_id'],'grant_count':sum(kind=='p' for kind,_ in desired(config,person)[1])}
