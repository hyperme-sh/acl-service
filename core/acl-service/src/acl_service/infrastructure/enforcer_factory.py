from __future__ import annotations

import uuid
from pathlib import Path

import casbin

from acl_service.infrastructure.casbin_adapter import TenantCasbinAdapter

_RESOURCES = Path(__file__).resolve().parent.parent / "resources"


def make_enforcer(
    sync_engine,
    tenant_id: uuid.UUID,
    *,
    model_file: str = "model_rbac.conf",
) -> casbin.Enforcer:
    model_path = _RESOURCES / model_file
    adapter = TenantCasbinAdapter(sync_engine, tenant_id)
    return casbin.Enforcer(str(model_path), adapter)


def enforce_rbac(
    sync_engine,
    tenant_id: uuid.UUID,
    sub: str,
    obj: str,
    act: str,
) -> bool:
    e = make_enforcer(sync_engine, tenant_id, model_file="model_rbac.conf")
    return bool(e.enforce(sub, obj, act))
