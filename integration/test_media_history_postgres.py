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
        revision, accounts = again.read_authority()
        assert revision == 2 and accounts['owner'].entries == (b'entry',)
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


def test_media_allocation_is_atomic_and_replay_safe(source, monkeypatch):
    import hashlib
    import importlib
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import Mock
    from acl_service.domain.history_store import AdmissionRejected
    # The admission bundle is built separately from the installed library. This
    # contract uses its source with native verification replaced by a fixed
    # verifier boundary; native signature contracts run in the admission lane.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'admission'))
    media = importlib.import_module('media_source')
    store, spec, url = source
    store.enroll('owner', b'genesis')
    authority = media.MediaSource(store, spec['tenant'], clock=lambda:100,
                                 identities=Mock(), native=tuple(Mock() for _ in range(5)))
    monkeypatch.setattr(authority, '_identities', Mock(return_value={'owner':'owner'}))
    record = {'object':'media_new', 'owner':'owner', 'issuedAt':100, 'sig':'signed'}
    scope = SimpleNamespace(tenant=spec['tenant'], owner='owner', object='media_new',
        ownership_digest=hashlib.sha256(media.encoded(record)).hexdigest(),
        policy_digest=hashlib.sha256(media.encoded({})).hexdigest())
    scope.claims=lambda:{'tenant':spec['tenant'],'owner':'owner','object':'media_new'}
    proof=SimpleNamespace(scope=scope, allocation=str(uuid4()), issued_at=100, expires_at=200)
    def consume(**kwargs):
        return authority.consume_allocation(spec['tenant'],'owner',record,{},10000,
                                             verify_grant=lambda _:proof, **kwargs)
    guards=0
    def cancel_commit():
        nonlocal guards
        guards+=1
        if guards==2:
            raise AdmissionRejected('cancelled at commit')
    with pytest.raises(AdmissionRejected):
        consume(cancel=cancel_commit)
    with store._transaction(write=False) as db:
        for table in ('media_sources','media_allocations','freshness.media_checkpoints','freshness.media_allocations'):
            assert db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _:consume(), range(2))) == [False, True]
    assert consume() is False
    engine=create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".media_allocations'))
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".media_sources'))
        with pytest.raises(HistoryConflict):
            consume()
    finally:
        engine.dispose()
