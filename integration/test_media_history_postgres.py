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


@pytest.mark.parametrize('refuse_at', [1, 2])
def test_provisioning_guard_rolls_back_both_scopes(migrated_sync_url, refuse_at):
    token=uuid4().hex
    spec=dict(history_schema='acl_h_'+token,checkpoint_schema='acl_c_'+token,
              tenant=str(uuid4()),source=str(uuid4()))
    calls=0
    def guard():
        nonlocal calls
        calls+=1
        if calls==refuse_at:
            raise ValueError('operator ownership lost')
    engine=create_engine(migrated_sync_url)
    try:
        with pytest.raises(ValueError,match='operator ownership lost'):
            provision_empty_media_source(migrated_sync_url,**spec,before_commit=guard)
        assert calls==refuse_at
        with engine.connect() as connection:
            names=connection.execute(text('SELECT nspname FROM pg_namespace WHERE nspname IN (:history,:checkpoint)'),
                dict(history=spec['history_schema'],checkpoint=spec['checkpoint_schema'])).fetchall()
            assert names==[]
        # The same declared scope can be provisioned after a rolled-back attempt.
        accepted=[]
        provision_empty_media_source(migrated_sync_url,**spec,before_commit=lambda:accepted.append(True))
        assert accepted==[True,True]
        store=PostgresHistoryStore(migrated_sync_url,**spec)
        try:assert store.read_authority()==(0,{})
        finally:store.close()
    finally:
        with engine.begin() as connection:
            for name in ('history_schema','checkpoint_schema'):
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{spec[name]}" CASCADE'))
        engine.dispose()


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


@pytest.mark.parametrize('active_index',[False,True])
def test_media_allocation_is_atomic_and_replay_safe(source, monkeypatch, request, active_index):
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
    if active_index:
        from acl_service.infrastructure.media_active_index import install_active_media_index
        install_active_media_index(url,**spec)
        store=PostgresHistoryStore(url,**spec,active_media_index=True)
        request.addfinalizer(store.close)
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
    if active_index:
        with store._transaction(write=False) as db:
            assert db.execute('SELECT object FROM freshness.media_active').fetchall()==[('media_new',)]
    engine=create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".media_allocations'))
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".media_sources'))
        with pytest.raises(HistoryConflict):
            consume()
    finally:
        engine.dispose()


def test_active_index_explicit_upgrade_fences_old_writers_and_preserves_checkpoints(source):
    import json
    from acl_service.domain.media_checkpoint import media_checkpoint_digest
    from acl_service.infrastructure.media_active_index import install_active_media_index
    store,spec,url=source
    with pytest.raises(StoreRejected):PostgresHistoryStore(url,**spec,active_media_index=True)
    docs={'active':{},'pending':{'deletion':{'owner':'owner'}},
          'done':{'deletion':{'cleanupComplete':True,'owner':'owner','command':'command','proofDigest':'digest','claims':{}}}}
    with store._transaction(write=False) as db:
        for object,doc in docs.items():
            row=(0,b'nonce',json.dumps(doc).encode())
            db.execute('INSERT INTO media_sources VALUES(?,?,?,?)',(object,*row))
            db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?)',
                       (object,media_checkpoint_digest(spec['tenant'],object,*row)))
    install_active_media_index(url,**spec)
    with pytest.raises(StoreRejected):store.read_authority()
    with pytest.raises(StoreRejected):PostgresHistoryStore(url,**spec)
    with pytest.raises(StoreRejected):install_active_media_index(url,**spec)
    current=PostgresHistoryStore(url,**spec,active_media_index=True)
    try:
        with current._transaction(write=False) as db:
            assert db.execute('SELECT object FROM freshness.media_active ORDER BY object').fetchall()==[('active',),('pending',)]
            assert db.execute('SELECT COUNT(*) FROM freshness.media_checkpoints').fetchone()==(3,)
            assert db.execute('SELECT COUNT(*) FROM media_sources').fetchone()==(3,)
    finally:current.close()


def test_active_index_upgrade_refuses_missing_primary_without_changing_mode(source):
    from acl_service.infrastructure.media_active_index import install_active_media_index
    store,spec,url=source
    with store._transaction(write=False) as db:
        db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?)',('missing',b'digest'))
    with pytest.raises(ValueError,match='checkpoint mismatch'):install_active_media_index(url,**spec)
    assert store.read_authority()==(0,{})


def test_active_startup_accepts_more_than_64_retained_tombstones(source,tmp_path):
    import json
    from types import SimpleNamespace
    from acl_service.domain.media_checkpoint import media_checkpoint_digest
    from acl_service.infrastructure.media_active_index import install_active_media_index
    from acl_service.infrastructure.media_postgres_settings import PostgresMediaSettings
    from acl_service.infrastructure.media_bindings import _provisioned
    _,spec,url=source
    install_active_media_index(url,**spec)
    settings=PostgresMediaSettings(url,**spec,active_media_index=True)
    config=tmp_path/'source.json';config.write_text('{}');config.chmod(0o600)
    key=tmp_path/'storage.key';key.write_text('private');key.chmod(0o600)
    binding=SimpleNamespace(postgres_file=config,key_file=key,postgres_settings=settings,tenant=spec['tenant'])
    current=settings.open()
    try:
        with current._transaction(write=False) as db:
            for i in range(66):
                object=str(i)
                doc={} if i==65 else {'deletion':{'cleanupComplete':True}}
                row=(0,b'nonce',json.dumps(doc).encode())
                db.execute('INSERT INTO media_sources VALUES(?,?,?,?)',(object,*row))
                db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?)',
                           (object,media_checkpoint_digest(spec['tenant'],object,*row)))
            db.execute('INSERT INTO freshness.media_active VALUES(?)',('65',))
        _provisioned(binding)
        with current._transaction(write=False) as db:db.execute('DELETE FROM media_sources WHERE object=?',('65',))
        with pytest.raises(ValueError,match='active checkpoint'):_provisioned(binding)
    finally:current.close()


def test_first_owner_is_atomic_absence_only_and_survives_restart(source):
    store,spec,url=source
    store.enroll_first_media_owner('existing-owner',b'signed-genesis',before_commit=lambda:None)
    assert store.read_authority()[1]['existing-owner'].entries==()
    again=PostgresHistoryStore(url,**spec)
    try:
        assert again.read('existing-owner').genesis==b'signed-genesis'
        for principal in ('existing-owner','another'):
            with pytest.raises(HistoryConflict):
                again.enroll_first_media_owner(principal,b'genesis',before_commit=lambda:None)
    finally:again.close()


def test_first_owner_cancellation_rolls_back_and_concurrency_has_one_winner(source):
    store,spec,url=source
    calls=0
    def cancel():
        nonlocal calls
        calls+=1
        if calls==2:raise RuntimeError('resolution changed')
    with pytest.raises(RuntimeError,match='resolution changed'):
        store.enroll_first_media_owner('owner',b'genesis',before_commit=cancel)
    assert store.read_authority()==(0,{})
    with store._transaction(write=False) as db:
        assert db.execute('SELECT 1 FROM freshness.ciphertext_heads').fetchall()==[]
    def admit(principal):
        try:
            store.enroll_first_media_owner(principal,b'genesis',before_commit=lambda:None)
            return True
        except HistoryConflict:return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(admit,['one','two']))==[False,True]
    assert len(store.read_authority()[1])==1


def test_first_owner_refuses_orphan_storage_rows_and_primary_rollback(source):
    store,spec,url=source
    with store._transaction(write=False) as db:
        db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?)',('old-object',b'digest'))
    with pytest.raises(HistoryConflict):
        store.enroll_first_media_owner('owner',b'genesis',before_commit=lambda:None)
    with store._transaction(write=False) as db:
        db.execute('DELETE FROM freshness.media_checkpoints')
    store.enroll_first_media_owner('owner',b'genesis',before_commit=lambda:None)
    engine=create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".history_accounts'))
        with pytest.raises(StoreRejected):
            store.enroll_first_media_owner('replacement',b'genesis',before_commit=lambda:None)
    finally:engine.dispose()


def test_credential_source_whole_domain_restart_and_rollback(source, monkeypatch):
    import json
    from pathlib import Path
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'admission'))
    from credential_source import CredentialSource
    store, spec, url = source
    store.enroll('one', b'{}')
    store.enroll('two', b'{}')
    credential = {'kind':'wallet','address':'test'}
    def verify(accounts, selected, at, policy):
        assert set(accounts) == {'one','two'}
        return {'heads':{owner:0 for owner in accounts},
                'snapshot':{'completeThrough':at,'credential':selected,'links':[],
                            'revocations':[],'history':{}}}
    def adapter(s):
        return CredentialSource(s,spec['tenant'],spec['source'],
            policy_at=lambda _:{'trust':{}},clock=lambda:100,verifier=verify)
    result = adapter(store).read(credential,100)
    again = PostgresHistoryStore(url, **spec)
    try:
        assert adapter(again).read(credential,100) == result
        engine = create_engine(url)
        try:
            with engine.begin() as db:
                db.execute(text(f'DELETE FROM "{spec["history_schema"]}".history_head_floors WHERE principal=:principal'), {'principal':'two'})
                db.execute(text(f'DELETE FROM "{spec["history_schema"]}".history_accounts WHERE principal=:principal'), {'principal':'two'})
            with pytest.raises(StoreRejected):
                adapter(again).read(credential,100)
        finally:
            engine.dispose()
    finally:
        again.close()
