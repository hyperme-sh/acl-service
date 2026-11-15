from dataclasses import replace

import pytest

from acl_service.infrastructure.group_media_journal import (
    GroupDocument, GroupMediaJournal, MAX_DOCUMENT, MAX_REVISION, group_checkpoint_digest,
)


def test_checkpoint_binds_every_scope_and_document_field():
    row = GroupDocument(1, b'n' * 32, b'{"rows":[]}')
    digest = group_checkpoint_digest('tenant', 'same-group', 'set_a', row)
    for tenant, predicate, group, changed in (
        ('other', 'same-group', 'set_a', row),
        ('tenant', 'named-circle', 'set_a', row),
        ('tenant', 'same-group', 'set_b', row),
        ('tenant', 'same-group', 'set_a', replace(row, revision=2)),
        ('tenant', 'same-group', 'set_a', replace(row, nonce=b'x' * 32)),
        ('tenant', 'same-group', 'set_a', replace(row, document=b'{"rows":[1]}')),
    ):
        assert group_checkpoint_digest(tenant, predicate, group, changed) != digest
    assert group_checkpoint_digest('tenant', 'same-group', 'set_a', row) == digest


@pytest.mark.parametrize('patch', [dict(revision=True), dict(revision=0), dict(revision=MAX_REVISION+1),
    dict(nonce=b'x'), dict(nonce=bytearray(32)), dict(document=b''), dict(document=b'x'*(MAX_DOCUMENT+1)),
    dict(document='not bytes')])
def test_invalid_checkpoint_fields_refuse(patch):
    with pytest.raises(ValueError):
        group_checkpoint_digest('tenant', 'same-group', 'set_a', replace(GroupDocument(1,b'n'*32,b'{}'), **patch))


@pytest.mark.parametrize('predicate,group', [('other','set_a'),('same-group','bad'),('same-group','set_'),('same-group','set_'+'x'*509)])
def test_invalid_scope_refuses(predicate,group):
    with pytest.raises(ValueError):
        group_checkpoint_digest('tenant', predicate, group, GroupDocument(1,b'n'*32,b'{}'))


def test_runtime_refuses_non_postgres_store():
    with pytest.raises(ValueError, match='PostgreSQL'):
        GroupMediaJournal(object())


def test_matching_schema_names_do_not_authorize_a_foreign_transaction():
    from types import SimpleNamespace
    from acl_service.infrastructure.postgres_history_store import _Connection
    store = SimpleNamespace(history_schema='history', checkpoint_schema='checkpoint')
    journal = object.__new__(GroupMediaJournal)
    journal.store = store
    class NeverExecute:
        def execute(self, *args):
            raise AssertionError('foreign transaction reached SQL')
    for origin in (None, SimpleNamespace(history_schema='history', checkpoint_schema='checkpoint')):
        db = _Connection(NeverExecute(), 'history', 'checkpoint', origin=origin)
        with pytest.raises(ValueError, match='scope changed'):
            journal.read(db, 'same-group', 'set_a')
        with pytest.raises(ValueError, match='scope changed'):
            journal.write(db, 'same-group', 'set_a', None, {})
