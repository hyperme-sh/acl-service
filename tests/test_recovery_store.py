"""One recovery storage contract exercised against two independent backends."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, RLock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from acl_service.domain.recovery_store import RecoverySession
from acl_service.infrastructure.recovery_repo import PostgresRecoveryStore
from test_review_boundaries_postgres import restricted_engine  # noqa: F401


class MemoryRecoveryStore:
    def __init__(self):
        self.rows = {}
        self.lock = RLock()

    def create_or_get_session(self, tenant_id, *, idempotency_key, metadata, ttl_minutes=30):
        with self.lock:
            key = (tenant_id, idempotency_key)
            if key not in self.rows:
                self.rows[key] = RecoverySession(uuid4(), 'pending', idempotency_key,
                    datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes))
            return self.rows[key]

    def transition_state(self, tenant_id, session_id, new_state):
        with self.lock:
            for key, row in self.rows.items():
                if key[0] == tenant_id and row.id == session_id:
                    self.rows[key] = replace(row, state=new_state)
                    return self.rows[key]
            return None


@pytest.fixture(params=['memory', 'postgres', 'postgres-rls'])
def store(request):
    if request.param == 'memory':
        yield MemoryRecoveryStore()
    elif request.param == 'postgres-rls':
        yield PostgresRecoveryStore(request.getfixturevalue('restricted_engine'))
    else:
        engine = create_engine(request.getfixturevalue('migrated_sync_url'))
        try:
            yield PostgresRecoveryStore(engine)
        finally:
            engine.dispose()


def test_retry_preserves_identity_state_and_expiry(store, seed):
    key = str(uuid4())
    original = store.create_or_get_session(seed.ta, idempotency_key=key, metadata=None)
    assert isinstance(original, RecoverySession)
    changed = store.transition_state(seed.ta, original.id, 'awaiting_proof')
    assert changed.id == original.id and changed.state == 'awaiting_proof'
    retry = store.create_or_get_session(seed.ta, idempotency_key=key, metadata={'retry': True}, ttl_minutes=90)
    assert retry == changed
    assert retry.expires_at == original.expires_at
    assert original.state == 'pending'  # Snapshot never mutates behind callers.


def test_cross_tenant_lookup_and_update_are_isolated(store, seed):
    key = str(uuid4())
    a = store.create_or_get_session(seed.ta, idempotency_key=key, metadata=None)
    b = store.create_or_get_session(seed.tb, idempotency_key=key, metadata=None)
    assert a.id != b.id
    assert store.transition_state(seed.tb, a.id, 'awaiting_proof') is None
    assert store.create_or_get_session(seed.ta, idempotency_key=key, metadata=None) == a
    assert store.transition_state(seed.ta, uuid4(), 'awaiting_proof') is None


def test_concurrent_same_key_creates_return_one_session(store, seed):
    key, barrier = str(uuid4()), Barrier(4)
    def create(_):
        barrier.wait(timeout=10)
        return store.create_or_get_session(seed.ta, idempotency_key=key, metadata=None)
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(create, range(4)))
    assert all(row == rows[0] for row in rows)
