from contextlib import contextmanager
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure import postgres_history_store as history
from acl_service.infrastructure.vault_statement_binding import SCOPE, VaultStatements, add_vault_statement_binding


def test_vault_statement_snapshot_is_default_off_and_read_only():
    assert add_vault_statement_binding(None, {}) is None
    owner = 'a' * 43 + '.' + 'b' * 43
    genesis = {'principal': owner, 'kind': 'genesis-epub', 'issuedAt': 1}
    db = Mock()
    db.execute.side_effect = lambda sql: (
        [(owner, json.dumps(genesis).encode())] if 'history_accounts' in sql else Mock(fetchone=lambda: None))
    close = Mock()

    @contextmanager
    def transaction(*, write, read_snapshot):
        assert not write and read_snapshot
        yield db

    store = SimpleNamespace(_transaction=transaction, close=close)
    source = VaultStatements(SimpleNamespace(tenant='tenant', open=lambda: store), owner, clock=lambda: 2)
    with pytest.raises(AdmissionRejected):
        source.append(SCOPE, 2, '', [], lambda: None)
    with pytest.raises(AdmissionRejected):
        source.read('forum', 2, lambda: None)
    response = source.read(SCOPE, 2, lambda: None)
    assert response['snapshot']['history']['accounts'][0]['genesisEpubBindings'] == [genesis]
    assert response['snapshot']['rows'] == []
    close.assert_called_once()


def test_vault_snapshot_preserves_source_and_checkpoint_checks_without_writer_locks():
    store = history.PostgresHistoryStore.__new__(history.PostgresHistoryStore)
    connection, db = Mock(), Mock()
    store.engine = SimpleNamespace(begin=lambda: snapshot_connection())
    store.tenant, store.source = 'tenant', 'source'
    store.active_media_index = False
    store.history_schema, store.checkpoint_schema = 'history', 'checkpoint'

    @contextmanager
    def snapshot_connection():
        yield connection

    marker = Mock(fetchone=lambda: ('tenant', 'source', 1))
    checkpoint = Mock(fetchone=lambda: (b'digest',))
    db.execute.side_effect = [marker, marker, checkpoint]
    with patch.object(history, '_Connection', return_value=db), \
            patch.object(history, 'authority_digest', return_value=b'digest') as digest:
        with store._transaction(write=False, read_snapshot=True) as snapshot:
            assert snapshot is db
        digest.assert_called_once_with(db)
    assert connection.exec_driver_sql.call_args_list[0].args == (
        'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY',
    )
    assert [call.args[0] for call in db.execute.call_args_list] == [
        'SELECT tenant,source,version FROM source_marker WHERE id=1',
        'SELECT tenant,source,version FROM freshness.source_marker WHERE id=1',
        'SELECT digest FROM freshness.authority_checkpoint WHERE id=1',
    ]
