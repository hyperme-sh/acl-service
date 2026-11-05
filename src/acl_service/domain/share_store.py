"""Tenant-scoped share storage and atomic active-use reservation.

Token lookup is an explicit capability crossing tenants. Returned snapshots omit
raw tokens and token hashes; creation returns the raw token once, separately.
Reservation commits before success and rechecks revocation, expiry and finite
uses while serializing competing consumers. Errors propagate, never grant access.
"""
from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class ShareRecord:
    id: UUID
    tenant_id: UUID
    token_prefix: str
    owner_user_id: UUID | None
    group_id: UUID | None
    resource_kind: str
    resource_descriptor: dict
    predicate_json: dict
    mode: str
    expires_at: datetime | None
    uses_remaining: int | None
    revoked_at: datetime | None
    created_by: str | None
    created_at: datetime


class ShareStore(Protocol):
    def create_share(self, *, tenant_id: UUID, resource_kind: str,
        resource_descriptor: dict, predicate_json: dict, mode: str,
        expires_at: datetime | None, uses_remaining: int | None,
        owner_user_id: UUID | None, group_id: UUID | None,
        created_by: str | None) -> tuple[ShareRecord, str]: ...
    def list_shares(self, tenant_id: UUID) -> list[ShareRecord]: ...
    def lookup_share_by_token_hash(self, token_hash: str) -> ShareRecord | None: ...
    def decrement_uses(self, tenant_id: UUID, share_id: UUID) -> bool: ...


def hash_share_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_share(store: ShareStore, **kwargs) -> tuple[ShareRecord, str]:
    return store.create_share(**kwargs)


def list_shares(store: ShareStore, tenant_id: UUID) -> list[ShareRecord]:
    return store.list_shares(tenant_id)


def lookup_share_by_token_hash(store: ShareStore, token_hash: str) -> ShareRecord | None:
    return store.lookup_share_by_token_hash(token_hash)


def decrement_uses(store: ShareStore, tenant_id: UUID, share_id: UUID) -> bool:
    return store.decrement_uses(tenant_id, share_id)
