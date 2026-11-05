from __future__ import annotations

import uuid
from pathlib import Path

import casbin

from acl_service.domain.policy_store import PolicyStore

_RESOURCES = Path(__file__).resolve().parent.parent / "resources"


def make_enforcer(
    store: PolicyStore,
    tenant_id: uuid.UUID,
    *,
    model_file: str = "model_rbac.conf",
) -> casbin.Enforcer:
    model_path = _RESOURCES / model_file
    model = casbin.Model()
    model.load_model(str(model_path))
    for row in store.list_rules(tenant_id):
        ptype = row.ptype
        if not ptype:
            continue
        section = ptype[:1]
        assertion = model.model.get(section, {}).get(ptype)
        if assertion is None:
            continue
        values = [getattr(row, f"v{i}") for i in range(6)]
        count = len(assertion.tokens)
        if any(v is None for v in values[:count]) or any(v is not None for v in values[count:]):
            continue
        model.add_policy(section, ptype, values[:count])
    enforcer = casbin.Enforcer(model)
    enforcer.build_role_links()
    return enforcer


def enforce_rbac(
    store: PolicyStore,
    tenant_id: uuid.UUID,
    sub: str,
    obj: str,
    act: str,
) -> bool:
    e = make_enforcer(store, tenant_id, model_file="model_rbac.conf")
    return bool(e.enforce(sub, obj, act))


def enforce_abac(
    store: PolicyStore,
    tenant_id: uuid.UUID,
    sub: str,
    obj: str,
    act: str,
    extra: str,
) -> bool:
    """ABAC enforce: extra maps to Casbin request field ``pol`` (policy row ``pol_req``)."""
    e = make_enforcer(store, tenant_id, model_file="model_abac.conf")
    return bool(e.enforce(sub, obj, act, extra))
