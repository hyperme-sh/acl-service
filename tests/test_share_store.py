"""Shared storage contract with real PostgreSQL and an independent test backend."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, RLock
from uuid import uuid4
import secrets
import pytest
from sqlalchemy import create_engine
from acl_service.domain.share_store import ShareRecord, hash_share_token
from acl_service.infrastructure.share_repo import PostgresShareStore
from test_review_boundaries_postgres import restricted_engine  # noqa: F401


class MemoryShareStore:
    def __init__(self):
        self.rows = {}
        self.lock = RLock()

    def create_share(self, **kwargs):
        with self.lock:
            token = secrets.token_urlsafe(32)
            hashed = hash_share_token(token)
            row = ShareRecord(id=uuid4(), token_prefix=hashed[:8], revoked_at=None,
                              created_at=datetime.now(timezone.utc), **deepcopy(kwargs))
            self.rows[hashed] = row
            return deepcopy(row), token

    def list_shares(self, tenant_id):
        with self.lock:
            return deepcopy(sorted((r for r in self.rows.values() if r.tenant_id == tenant_id),
                                   key=lambda r: r.created_at, reverse=True))

    def lookup_share_by_token_hash(self, hashed):
        with self.lock:
            return deepcopy(self.rows.get(hashed))

    def decrement_uses(self, tenant_id, share_id):
        with self.lock:
            for key, row in self.rows.items():
                if row.id != share_id or row.tenant_id != tenant_id:
                    continue
                if row.revoked_at or (row.expires_at and row.expires_at <= datetime.now(timezone.utc)):
                    return False
                if row.uses_remaining is not None:
                    if row.uses_remaining <= 0:
                        return False
                    self.rows[key] = replace(row, uses_remaining=row.uses_remaining - 1)
                return True
            return False


@pytest.fixture(params=['memory', 'postgres', 'postgres-rls'])
def store(request):
    if request.param == 'memory':
        yield MemoryShareStore()
    elif request.param == 'postgres-rls':
        yield PostgresShareStore(request.getfixturevalue('restricted_engine'))
    else:
        engine = create_engine(request.getfixturevalue('migrated_sync_url'))
        try:
            yield PostgresShareStore(engine)
        finally:
            engine.dispose()


def create(store, tenant, **overrides):
    args = dict(tenant_id=tenant, resource_kind='document', resource_descriptor={'name': 'test'},
        predicate_json={}, mode='release_if_match', expires_at=None, uses_remaining=1,
        owner_user_id=None, group_id=None, created_by='synthetic')
    args.update(overrides)
    return store.create_share(**args)


def test_snapshot_token_boundary_and_tenant_scope(store, seed):
    row, token = create(store, seed.ta)
    assert isinstance(row, ShareRecord)
    assert not hasattr(row, 'token_hash') and not hasattr(row, 'token')
    assert store.lookup_share_by_token_hash(hash_share_token(token)) == row
    assert store.lookup_share_by_token_hash(hash_share_token('not-a-token')) is None
    assert row not in store.list_shares(seed.tb)
    assert not store.decrement_uses(seed.tb, row.id)
    row.resource_descriptor['name'] = 'modified snapshot'
    assert store.lookup_share_by_token_hash(hash_share_token(token)).resource_descriptor == {'name': 'test'}


def test_one_use_has_exactly_one_concurrent_winner(store, seed):
    row, token = create(store, seed.ta)
    barrier = Barrier(6)
    def consume(_):
        barrier.wait(timeout=10)
        return store.decrement_uses(seed.ta, row.id)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(consume, range(6)))
    assert results.count(True) == 1
    assert store.lookup_share_by_token_hash(hash_share_token(token)).uses_remaining == 0
    assert not store.decrement_uses(seed.ta, row.id)


def test_expired_and_unlimited_reservations(store, seed):
    expired, _ = create(store, seed.ta, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not store.decrement_uses(seed.ta, expired.id)
    unlimited, token = create(store, seed.ta, uses_remaining=None)
    assert all(store.decrement_uses(seed.ta, unlimited.id) for _ in range(3))
    assert store.lookup_share_by_token_hash(hash_share_token(token)).uses_remaining is None
