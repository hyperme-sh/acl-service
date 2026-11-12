"""Nightly PostgreSQL checks; never run against a supplied live database."""
from concurrent.futures import ThreadPoolExecutor
import uuid
import os
import importlib.util
import pytest
from sqlalchemy import create_engine, text
from alembic.migration import MigrationContext
from alembic.operations import Operations
from acl_service.infrastructure.contact_lane_store import PostgresContactLaneStore
from acl_service.infrastructure.first_contact_store import PostgresFirstContactStore, LaneCapacity


def test_lane_atomic_quota_retry_and_expiry(migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    store = PostgresFirstContactStore(engine)
    # The database owner keeps migrations in its checkout, outside runtime wheels.
    # Exercise the actual additive owner migration on this disposable database.
    spec = importlib.util.spec_from_file_location('contact_schema', os.environ['SOCIACL_FIRST_CONTACT_SCHEMA'])
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with engine.begin() as cx:
        if not cx.execute(text("SELECT to_regclass('sociacl_first_contact_messages')")).scalar_one():
            with Operations.context(MigrationContext.configure(cx)):
                migration.upgrade()
    base_spec = importlib.util.spec_from_file_location('private_contact_schema', os.environ['SOCIACL_CONTACT_SCHEMA'])
    base = importlib.util.module_from_spec(base_spec)
    base_spec.loader.exec_module(base)
    with engine.begin() as cx:
        if not cx.execute(text("SELECT to_regclass('sociacl_contact_messages')")).scalar_one():
            with Operations.context(MigrationContext.configure(cx)):
                base.upgrade()
    private = PostgresContactLaneStore(engine)
    lane = uuid.uuid4().hex + uuid.uuid4().hex
    def append(i):
        try:
            return store.append(lane, i.to_bytes(94, 'big'))
        except LaneCapacity:
            return None
    try:
        private.append(lane, b'p' * 32)
        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted = [v for v in pool.map(append, range(40)) if v]
        assert len(accepted) == 10
        assert len(private.read(lane)) == 1
        private.append(lane, b'q' * 32)
        assert len(private.read(lane)) == 2
        rows = store.read(lane)
        assert len(rows) == 10
        first = rows[0]
        assert store.append(lane, first['ciphertext']) == first['id']
        assert len(store.read(lane)) == 10
        assert store.read('ff' * 32) == []
        with engine.begin() as cx:
            cx.execute(text("UPDATE sociacl_first_contact_messages SET created_at=now()-interval '8 days', expires_at=now()-interval '1 day' WHERE lane_id=:lane"), {'lane': lane})
        assert store.read(lane) == []
        assert append(100) is not None
        assert len(store.read(lane)) == 1
    finally:
        with engine.begin() as cx:
            cx.execute(text('DELETE FROM sociacl_first_contact_messages WHERE lane_id=:lane'), {'lane': lane})
            cx.execute(text('DELETE FROM sociacl_contact_messages WHERE lane_id=:lane'), {'lane': lane})
        engine.dispose()
