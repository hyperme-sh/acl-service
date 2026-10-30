"""Casbin SQLAlchemy adapter scoped to one tenant + RLS GUC per session."""

from __future__ import annotations

import uuid
from contextlib import contextmanager

from casbin import persist
from casbin_sqlalchemy_adapter.adapter import Adapter
from sqlalchemy import text

from controlplane_db.models import AclCasbinRule


class TenantCasbinAdapter(Adapter):
    """Loads/saves only rows for ``tenant_id``; sets ``app.current_tenant_id`` each session."""

    def __init__(self, engine, tenant_id: uuid.UUID) -> None:
        self._tenant_uuid = tenant_id
        super().__init__(
            engine,
            db_class=AclCasbinRule,
            create_all_models=False,
        )

    @contextmanager
    def _session_scope(self):
        session = self.session_local()
        try:
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(self._tenant_uuid)},
            )
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def _filter_tenant(self, query):
        return query.filter(self._db_class.tenant_id == self._tenant_uuid)

    def load_policy(self, model):
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._filter_tenant(query)
            query = self._softdelete_query(query)
            for line in query.order_by(self._db_class.id).all():
                persist.load_policy_line(str(line), model)

    def load_filtered_policy(self, model, filter) -> None:
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._filter_tenant(query)
            query = self._softdelete_query(query)
            query = self.filter_query(query, filter)
            for line in query.all():
                persist.load_policy_line(str(line), model)
            self._filtered = True

    def _save_policy_line(self, ptype, rule, session=None):
        line = self._db_class(ptype=ptype, tenant_id=self._tenant_uuid)
        for i, v in enumerate(rule):
            setattr(line, f"v{i}", v)
        if session:
            session.add(line)
        else:
            with self._session_scope() as s:
                s.add(line)

    def save_policy(self, model):
        if self.softdelete_attribute is not None:
            return super().save_policy(model)
        with self._session_scope() as session:
            q = self._filter_tenant(session.query(self._db_class))
            q.delete(synchronize_session=False)
            for sec in ("p", "g"):
                if sec not in model.model.keys():
                    continue
                for ptype, ast in model.model[sec].items():
                    for rule in ast.policy:
                        self._save_policy_line(ptype, rule, session=session)
        return True

    def remove_policy(self, sec, ptype, rule):
        with self._session_scope() as session:
            query = self._filter_tenant(session.query(self._db_class))
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)
            for i, v in enumerate(rule):
                query = query.filter(getattr(self._db_class, f"v{i}") == v)
            r = query.delete(synchronize_session=False)
        return r > 0

    def remove_policies(self, sec, ptype, rules):
        if not rules:
            return
        for rule in rules:
            self.remove_policy(sec, ptype, rule)

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        with self._session_scope() as session:
            query = self._filter_tenant(session.query(self._db_class))
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)
            if not (0 <= field_index <= 5):
                return False
            if not (1 <= field_index + len(field_values) <= 6):
                return False
            for i, v in enumerate(field_values):
                if v != "":
                    col = getattr(self._db_class, f"v{field_index + i}")
                    query = query.filter(col == v)
            r = query.delete(synchronize_session=False)
        return r > 0

    def update_policy(self, sec: str, ptype: str, old_rule: list[str], new_rule: list[str]) -> None:
        with self._session_scope() as session:
            query = self._filter_tenant(session.query(self._db_class))
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)
            for index, value in enumerate(old_rule):
                col = getattr(self._db_class, f"v{index}")
                query = query.filter(col == value)
            old_line = query.one()
            longest = old_rule if len(old_rule) > len(new_rule) else new_rule
            for index in range(len(longest)):
                if index < len(new_rule):
                    setattr(old_line, f"v{index}", new_rule[index])
                else:
                    setattr(old_line, f"v{index}", None)
