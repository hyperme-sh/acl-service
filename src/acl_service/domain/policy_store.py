"""Tenant-scoped policy storage API; no database or transport types cross it.

Successful mutations are committed and visible to subsequent reads. Implementations
must isolate tenants, make identical inserts idempotent, delete exact rules, and
propagate storage failures. Event publication is a separate, retryable operation.
"""
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class PolicyRecord:
    id: int
    ptype: str | None
    v0: str | None = None
    v1: str | None = None
    v2: str | None = None
    v3: str | None = None
    v4: str | None = None
    v5: str | None = None


class PolicyStore(Protocol):
    def list_rules(self, tenant_id: UUID) -> list[PolicyRecord]: ...
    def add_rule(self, tenant_id: UUID, ptype: str, rule: list[str]) -> PolicyRecord: ...
    def add_rule_if_absent(self, tenant_id: UUID, ptype: str, rule: list[str]) -> bool: ...
    def delete_rule(self, tenant_id: UUID, ptype: str, rule: list[str]) -> bool: ...


def list_rules(store: PolicyStore, tenant_id: UUID) -> list[PolicyRecord]:
    return store.list_rules(tenant_id)


def add_rule(store: PolicyStore, tenant_id: UUID, ptype: str, rule: list[str]) -> PolicyRecord:
    return store.add_rule(tenant_id, ptype, rule)


def add_rule_if_absent(store: PolicyStore, tenant_id: UUID, ptype: str, rule: list[str]) -> bool:
    return store.add_rule_if_absent(tenant_id, ptype, rule)


def delete_rule(store: PolicyStore, tenant_id: UUID, ptype: str, rule: list[str]) -> bool:
    return store.delete_rule(tenant_id, ptype, rule)
