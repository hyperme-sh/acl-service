"""Nightly PostgreSQL checks; never run against a supplied live database."""
from concurrent.futures import ThreadPoolExecutor
import uuid
import os
import importlib.util
import pytest
from sqlalchemy import create_engine, text
from alembic.migration import MigrationContext
from alembic.operations import Operations
from acl_service.infrastructure.contact_lane_store import PostgresContactLaneStore, LaneCapacity


def test_lane_atomic_quota_retry_and_expiry(migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    store = PostgresContactLaneStore(engine)
    # The database owner keeps migrations in its checkout, outside runtime wheels.
    # Exercise the actual additive owner migration on this disposable database.
    spec = importlib.util.spec_from_file_location('contact_schema', os.environ['SOCIACL_CONTACT_SCHEMA'])
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with engine.begin() as cx:
        if not cx.execute(text("SELECT to_regclass('sociacl_contact_messages')")).scalar_one():
            with Operations.context(MigrationContext.configure(cx)):
                migration.upgrade()
    lane = uuid.uuid4().hex + uuid.uuid4().hex
    def append(i):
        try:
            return store.append(lane, i.to_bytes(32, 'big'))
        except LaneCapacity:
            return None
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted = [v for v in pool.map(append, range(40)) if v]
        assert len(accepted) == 30
        rows = store.read(lane)
        assert len(rows) == 30
        first = rows[0]
        assert store.append(lane, first['ciphertext']) == first['id']
        assert len(store.read(lane)) == 30
        assert store.read('ff' * 32) == []
        with engine.begin() as cx:
            cx.execute(text("UPDATE sociacl_contact_messages SET created_at=now()-interval '8 days', expires_at=now()-interval '1 day' WHERE lane_id=:lane"), {'lane': lane})
        assert store.read(lane) == []
        assert append(100) is not None
        assert len(store.read(lane)) == 1
    finally:
        with engine.begin() as cx:
            cx.execute(text('DELETE FROM sociacl_contact_messages WHERE lane_id=:lane'), {'lane': lane})
        engine.dispose()
