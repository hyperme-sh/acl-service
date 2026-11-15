"""Group allocation journal input and conflict unit contracts."""
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID
import pytest
from acl_service.infrastructure.group_allocation_journal import GroupAllocationJournal
from acl_service.domain.history_store import HistoryConflict


def setup():
    journal=object.__new__(GroupAllocationJournal)
    journal.store=SimpleNamespace(history_schema='history',checkpoint_schema='checkpoint')
    db=Mock(origin=journal.store,history='history',checkpoint='checkpoint')
    db.execute.return_value.fetchall.return_value=[]
    db.execute.return_value.fetchone.return_value=(0,)
    return journal,db


def test_invalid_inputs_never_reach_sql():
    with pytest.raises(ValueError): GroupAllocationJournal(object())
    journal,db=setup()
    for allocation,predicate,set_id,digest in [(None,'same-group','set_a',b'a'*32),
            (str(UUID(int=0)),'same-group','set_a',b'a'*32),
            (str(UUID(int=1)),'bad','set_a',b'a'*32),
            (str(UUID(int=1)),'same-group','bad',b'a'*32),
            (str(UUID(int=1)),'same-group','set_a',b'a')]:
        with pytest.raises(ValueError): journal.consume(db,allocation,predicate,set_id,digest)
    db.execute.assert_not_called()
    db.origin=object()
    with pytest.raises(ValueError): journal.consume(db,str(UUID(int=1)),'same-group','set_a',b'a'*32)
    db.execute.assert_not_called()


def test_exact_replay_conflicting_checkpoint_and_capacity():
    journal,db=setup();args=(str(UUID(int=1)),'same-group','set_a',b'a'*32)
    db.execute.return_value.fetchall.return_value=[args]
    assert journal.consume(db,*args) is False
    db.execute.return_value.fetchall.side_effect=[[args],[]]
    with pytest.raises(HistoryConflict): journal.consume(db,*args)
    db.execute.return_value.fetchall.side_effect=None
    db.execute.return_value.fetchall.return_value=[]
    db.execute.return_value.fetchone.return_value=(64,)
    with pytest.raises(HistoryConflict): journal.consume(db,*args)
