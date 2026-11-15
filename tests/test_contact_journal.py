from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.contact_journal import (
    ContactDocument, ContactJournal, MAX_OWNERS, MAX_REVISION, contact_digest,
)

OWNER = 'a' * 43 + '.' + 'b' * 43
ROW = ContactDocument(1, b'n' * 32, b'c' * 28)


def journal():
    result = object.__new__(ContactJournal)
    result.store = SimpleNamespace(tenant='tenant', source='source', history_schema='history', checkpoint_schema='checkpoint')
    db = Mock(origin=result.store, history='history', checkpoint='checkpoint')
    return result, db


def test_checkpoint_binds_owner_source_kind_revision_and_bytes():
    digest = contact_digest('tenant', 'source', OWNER, 'vault', ROW)
    for tenant, source, owner, kind, row in (
        ('other', 'source', OWNER, 'vault', ROW), ('tenant', 'other', OWNER, 'vault', ROW),
        ('tenant', 'source', OWNER[::-1], 'vault', ROW), ('tenant', 'source', OWNER, 'descriptor', ROW),
        ('tenant', 'source', OWNER, 'vault', replace(ROW, revision=2)),
        ('tenant', 'source', OWNER, 'vault', replace(ROW, nonce=b'x'*32)),
        ('tenant', 'source', OWNER, 'vault', replace(ROW, payload=b'd'*28)),
    ):
        assert contact_digest(tenant, source, owner, kind, row) != digest


@pytest.mark.parametrize('patch', [dict(revision=True), dict(revision=0), dict(revision=MAX_REVISION+1),
    dict(nonce=b'x'), dict(payload=b'x'*27), dict(payload=b'x'*(1024*1024+1)), dict(payload=bytearray(28))])
def test_invalid_ciphertext_documents_refuse(patch):
    with pytest.raises(ValueError): contact_digest('tenant', 'source', OWNER, 'vault', replace(ROW, **patch))


def test_foreign_transaction_is_not_authorized_by_matching_schemas():
    j, db = journal()
    db.origin = object()
    with pytest.raises(ValueError): j.read(db, OWNER, 'vault')
    with pytest.raises(ValueError): j.write(db, OWNER, 'vault', None, ROW.payload)
    db.execute.assert_not_called()


@pytest.mark.parametrize('raw,checkpoint', [(None, (b'digest',)), ((1,ROW.nonce,ROW.payload), None),
    ((1,ROW.nonce,ROW.payload), (b'wrong',))])
def test_missing_or_mismatched_document_checkpoint_refuses(raw, checkpoint):
    j, db = journal()
    db.execute.side_effect = [Mock(fetchone=lambda: raw), Mock(fetchone=lambda: checkpoint)]
    with pytest.raises(HistoryConflict): j.read(db, OWNER, 'vault')


def test_read_returns_only_matched_committed_bytes():
    j, db = journal()
    db.execute.side_effect = [Mock(fetchone=lambda: (1,ROW.nonce,ROW.payload)),
        Mock(fetchone=lambda: (j._digest(OWNER,'vault',ROW),))]
    assert j.read(db, OWNER, 'vault') == ROW


def test_stale_write_refuses_before_any_mutation():
    j, db = journal()
    j.read = Mock(return_value=ROW)
    with pytest.raises(HistoryConflict): j.write(db, OWNER, 'vault', None, b'x'*28)
    db.execute.assert_not_called()


def test_revision_exhaustion_refuses_without_a_write():
    j, db = journal()
    row = replace(ROW, revision=MAX_REVISION)
    j.read = Mock(return_value=row)
    with pytest.raises(ValueError): j.write(db, OWNER, 'vault', row, b'x'*28)
    db.execute.assert_not_called()


def test_capacity_counts_both_documents_and_checkpoints():
    j, db = journal()
    j.read = Mock(return_value=None)
    db.execute.side_effect = [Mock(fetchone=lambda: (MAX_OWNERS,)), Mock(fetchone=lambda: None)]
    with pytest.raises(ValueError,match='capacity'): j.write(db, OWNER, 'vault', None, ROW.payload)
    assert db.execute.call_count == 2


def test_existing_owner_may_add_second_kind_at_capacity():
    j, db = journal()
    j.read = Mock(return_value=None)
    db.execute.side_effect = [Mock(fetchone=lambda: (MAX_OWNERS,)), Mock(fetchone=lambda: (1,)), Mock(), Mock()]
    saved = j.write(db, OWNER, 'vault', None, ROW.payload)
    assert saved.revision == 1 and saved.payload == ROW.payload
    assert db.execute.call_count == 4


@pytest.mark.parametrize('counts', [(0,), (1,0)])
def test_lost_document_or_checkpoint_update_aborts(counts):
    j, db = journal()
    j.read = Mock(return_value=ROW)
    db.execute.side_effect = [Mock(rowcount=n) for n in counts]
    with pytest.raises(HistoryConflict): j.write(db, OWNER, 'vault', ROW, ROW.payload)


def test_successful_cas_updates_both_scopes_once():
    j, db = journal()
    j.read = Mock(return_value=ROW)
    db.execute.side_effect = [Mock(rowcount=1), Mock(rowcount=1)]
    saved = j.write(db, OWNER, 'vault', ROW, b'x'*28)
    assert saved.revision == 2 and saved.payload == b'x'*28
    assert db.execute.call_count == 2


def test_non_postgres_runtime_refuses():
    with pytest.raises(ValueError,match='PostgreSQL'): ContactJournal(object())


def test_installer_preserves_existing_source_version():
    from contextlib import nullcontext
    from unittest.mock import patch
    from acl_service.infrastructure.contact_journal import install_contact_journal
    store=Mock()
    store._transaction.return_value=nullcontext(Mock())
    with patch('acl_service.infrastructure.contact_journal.PostgresHistoryStore',return_value=store) as constructor:
        install_contact_journal('private',history_schema='history',checkpoint_schema='checkpoint',tenant='tenant',source='source',active_media_index=True)
        assert constructor.call_args.kwargs['active_media_index'] is True
    store.close.assert_called_once()
