"""Protected history contracts on the CI-owned disposable PostgreSQL database."""
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source


@pytest.fixture
def source(migrated_sync_url):
    token = uuid4().hex
    spec = dict(history_schema='acl_h_' + token, checkpoint_schema='acl_c_' + token,
                tenant=str(uuid4()), source=str(uuid4()))
    provision_empty_media_source(migrated_sync_url, **spec)
    store = PostgresHistoryStore(migrated_sync_url, **spec)
    try:
        yield store, spec, migrated_sync_url
    finally:
        store.close()
        engine = create_engine(migrated_sync_url)
        with engine.begin() as db:
            for name in ('history_schema', 'checkpoint_schema'):
                db.execute(text(f'DROP SCHEMA IF EXISTS "{spec[name]}" CASCADE'))
        engine.dispose()


def test_restart_history_ciphertext_and_stale_revision(source):
    store, spec, url = source
    store.enroll('owner', b'genesis')
    store.append('owner', 0, b'entry', authority_revision=1, verified_rotation=1)
    store.write_verified_ciphertext('owner', 'wraps', b'opaque', generation=0, head=1, authority_revision=2)
    again = PostgresHistoryStore(url, **spec)
    try:
        assert again.read('owner').entries == (b'entry',)
        assert again.read_ciphertext('owner', 'wraps') == (1, b'opaque')
        with pytest.raises(HistoryConflict):
            again.append('owner', 0, b'stale', authority_revision=1)
        with pytest.raises(StoreRejected):
            again.write_verified_ciphertext('owner', 'wraps', b'stale', generation=0, head=1, authority_revision=2)
        assert again.read_ciphertext('owner', 'wraps') == (1, b'opaque')
    finally:
        again.close()


def test_absence_only_provision_and_source_binding(source):
    store, spec, url = source
    with pytest.raises(Exception):
        provision_empty_media_source(url, **spec)
    for field in ('tenant', 'source'):
        with pytest.raises(StoreRejected):
            PostgresHistoryStore(url, **{**spec, field: str(uuid4())})
    assert store.read_authority() == (0, {})


def test_missing_scope_is_not_recreated(source):
    store, spec, url = source
    engine = create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{spec["checkpoint_schema"]}" CASCADE'))
        with pytest.raises(StoreRejected):
            PostgresHistoryStore(url, **spec)
        with pytest.raises(StoreRejected):
            store.read_authority()
        with engine.connect() as db:
            assert db.execute(text('SELECT 1 FROM pg_namespace WHERE nspname=:name'),
                              {'name': spec['checkpoint_schema']}).fetchone() is None
    finally:
        engine.dispose()


def test_history_rollback_refuses_against_independent_checkpoint(source):
    store, spec, url = source
    store.enroll('owner', b'genesis')
    store.append('owner', 0, b'current')
    engine = create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".history_entries'))
        with pytest.raises(StoreRejected):
            store.read_authority()
        with pytest.raises(StoreRejected):
            PostgresHistoryStore(url, **spec)
    finally:
        engine.dispose()


def test_parallel_append_has_one_winner_and_cancel_rolls_back(source):
    store, spec, url = source
    store.enroll('owner', b'genesis')
    def append(value):
        try:
            store.append('owner', 0, value, authority_revision=1)
            return True
        except HistoryConflict:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(append, (b'a', b'b'))) == [False, True]
    def cancel():
        raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError, match='cancelled'):
        store.write_verified_ciphertext('owner', 'wraps', b'opaque', generation=0,
                                        head=1, authority_revision=2, before_commit=cancel)
    assert store.read_ciphertext('owner', 'wraps') == (0, b'')
    with store._transaction(write=False) as db:
        assert db.execute('SELECT head FROM history_head_floors').fetchall() == []
