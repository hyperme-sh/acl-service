"""Group source persistence contracts use only CI-owned disposable PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.group_media_journal import GroupMediaJournal, install_group_media_journal
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source


@pytest.fixture
def group_source(migrated_sync_url):
    token=uuid4().hex
    spec=dict(history_schema='acl_gh_'+token, checkpoint_schema='acl_gc_'+token,
              tenant=str(uuid4()), source=str(uuid4()))
    provision_empty_media_source(migrated_sync_url, **spec)
    store=PostgresHistoryStore(migrated_sync_url, **spec)
    try:
        with pytest.raises(StoreRejected):
            GroupMediaJournal(store)
        install_group_media_journal(migrated_sync_url, **spec)
        yield store, GroupMediaJournal(store), spec, migrated_sync_url
    finally:
        store.close()
        engine=create_engine(migrated_sync_url)
        with engine.begin() as db:
            for name in ('history_schema','checkpoint_schema'):
                db.execute(text(f'DROP SCHEMA IF EXISTS "{spec[name]}" CASCADE'))
        engine.dispose()


def test_restart_exact_cas_and_independent_group_scopes(group_source):
    store,journal,spec,url=group_source
    with store._transaction(write=True) as db:
        first=journal.write(db,'same-group','set_a',None,{'rows':[]})
        other=journal.write(db,'named-circle','set_a',None,{'rows':[1]})
    again=PostgresHistoryStore(url, **spec)
    try:
        restarted=GroupMediaJournal(again)
        with again._transaction(write=False) as db:
            assert restarted.read(db,'same-group','set_a')==first
            assert restarted.read(db,'named-circle','set_a')==other
        with again._transaction(write=True) as db:
            second=restarted.write(db,'same-group','set_a',first,{'rows':[2]})
        assert second.revision==2 and second.nonce!=first.nonce
        with pytest.raises(HistoryConflict), again._transaction(write=True) as db:
            restarted.write(db,'same-group','set_a',first,{'rows':[3]})
        with pytest.raises(StoreRejected):
            install_group_media_journal(url, **spec)
        with again._transaction(write=False) as db:
            assert restarted.read(db,'same-group','set_a')==second
    finally:
        again.close()


def test_concurrent_creation_and_cancelled_commit(group_source):
    store,journal,_,_=group_source
    def create(value):
        try:
            with store._transaction(write=True) as db:
                journal.write(db,'same-group','set_a',None,{'value':value})
            return True
        except HistoryConflict:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(create,('a','b')))==[False,True]
    def cancel():
        raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError,match='cancelled'), store._transaction(write=True,before_commit=cancel) as db:
        journal.write(db,'same-group','set_b',None,{'rows':[]})
    with store._transaction(write=False) as db:
        assert journal.read(db,'same-group','set_b') is None


@pytest.mark.parametrize('damage', ['rollback','missing','checkpoint','swapped'])
def test_independent_checkpoint_refuses_restored_or_substituted_document(group_source,damage):
    store,journal,spec,url=group_source
    with store._transaction(write=True) as db:
        first=journal.write(db,'same-group','set_a',None,{'value':1})
        journal.write(db,'same-group','set_a',first,{'value':2})
        journal.write(db,'same-group','set_b',None,{'value':3})
    engine=create_engine(url)
    try:
        with engine.begin() as db:
            table=f'"{spec["history_schema"]}".group_media_sources'
            checkpoint=f'"{spec["checkpoint_schema"]}".group_media_checkpoints'
            if damage=='rollback':
                db.execute(text(f"UPDATE {table} SET revision=:revision,nonce=:nonce,document=:document WHERE set_id='set_a'"),dict(revision=first.revision,nonce=first.nonce,document=first.document))
            elif damage=='missing':
                db.execute(text(f"DELETE FROM {table} WHERE set_id='set_a'"))
            elif damage=='checkpoint':
                db.execute(text(f"DELETE FROM {checkpoint} WHERE set_id='set_a'"))
            else:
                db.execute(text(f"UPDATE {checkpoint} SET digest=(SELECT digest FROM {checkpoint} WHERE set_id='set_b') WHERE set_id='set_a'"))
        with pytest.raises(HistoryConflict), store._transaction(write=False) as db:
            journal.read(db,'same-group','set_a')
        with pytest.raises(HistoryConflict), store._transaction(write=True) as db:
            journal.write(db,'same-group','set_a',None,{'rows':[]})
    finally:
        engine.dispose()


def test_group_capacity_and_payload_refusal_preserve_current_document(group_source):
    store,journal,_,_=group_source
    with store._transaction(write=True) as db:
        for i in range(64):journal.write(db,'same-group',f'set_{i}',None,{'rows':[]})
    with pytest.raises(ValueError,match='capacity'), store._transaction(write=True) as db:
        journal.write(db,'same-group','set_extra',None,{'rows':[]})
    for payload in [[], {'value':float('nan')}, {'value':'x'*(4*1024*1024)}]:
        with pytest.raises(ValueError), store._transaction(write=True) as db:
            held=journal.read(db,'same-group','set_0')
            journal.write(db,'same-group','set_0',held,payload)
    with store._transaction(write=False) as db:
        assert journal.read(db,'same-group','set_0').revision==1
