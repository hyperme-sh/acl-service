"""Group allocation persistence contracts run on CI disposable PostgreSQL."""
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, text
from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.group_allocation_journal import GroupAllocationJournal, install_group_allocation_journal
from test_group_media_journal import group_source


def test_atomic_consumption_replay_and_rollback(group_source):
    store, groups, spec, url = group_source
    with pytest.raises(StoreRejected): GroupAllocationJournal(store)
    install_group_allocation_journal(url, **spec)
    journal = GroupAllocationJournal(store)
    allocation = str(uuid4())
    with store._transaction(write=True) as db:
        assert journal.consume(db, allocation, 'same-group', 'set_a', b'a'*32)
        groups.write(db, 'same-group', 'set_a', None, {'allocation': allocation})
    with store._transaction(write=True) as db:
        assert not journal.consume(db, allocation, 'same-group', 'set_a', b'a'*32)
    for args in [(allocation,'named-circle','set_a',b'a'*32), (allocation,'same-group','set_b',b'a'*32),
                 (str(uuid4()),'same-group','set_a',b'a'*32), (allocation,'same-group','set_a',b'b'*32)]:
        with pytest.raises(HistoryConflict), store._transaction(write=True) as db:
            journal.consume(db,*args)
    other = str(uuid4())
    with pytest.raises(RuntimeError), store._transaction(write=True) as db:
        journal.consume(db, other, 'same-group', 'set_b', b'b'*32)
        raise RuntimeError('cancelled before group update')
    with store._transaction(write=True) as db:
        assert journal.consume(db, other, 'same-group', 'set_b', b'b'*32)
    engine=create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text(f'DELETE FROM "{spec["history_schema"]}".group_allocations WHERE set_id=\'set_a\''))
        with pytest.raises(HistoryConflict), store._transaction(write=True) as db:
            journal.consume(db, allocation, 'same-group', 'set_a', b'a'*32)
    finally: engine.dispose()
