"""Pure SQL binding and source identifier unit checks; no database access."""
from contextlib import contextmanager
from unittest.mock import MagicMock, Mock

import pytest

from acl_service.infrastructure.postgres_history_store import _Connection, scope_name


@pytest.mark.parametrize('value', ['', 'public', 'acl_x;DROP SCHEMA public', 'acl_A', 'acl_' + 'x'*49, None])
def test_schema_names_reject_untrusted_identifiers(value):
    with pytest.raises(ValueError):
        scope_name(value)


def test_fixed_sql_binding_does_not_interpolate_values():
    connection = Mock()
    db = _Connection(connection, 'acl_history', 'acl_checkpoint')
    opaque = "value'; DROP TABLE history_accounts --"
    db.execute('SELECT genesis FROM main.history_accounts WHERE principal=?', (opaque,))
    statement, params = connection.execute.call_args.args
    assert str(statement) == 'SELECT genesis FROM acl_history.history_accounts WHERE principal=:p0'
    assert params == {'p0': opaque}
    db.executemany('INSERT INTO freshness.ciphertext_heads VALUES(?,?,0,?)', [('a', 'wraps', b'x'), ('b', 'wraps', b'y')])
    assert connection.execute.call_count == 3
    assert str(connection.execute.call_args.args[0]).startswith('INSERT INTO acl_checkpoint.')
    with pytest.raises(ValueError):
        db.execute('SELECT ?', ())


@pytest.mark.parametrize('backend', ['store', 'provision-media', 'provision-statements'])
def test_non_postgres_and_invalid_scopes_refuse_before_connecting(backend):
    from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
    from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source, provision_empty_statement_source
    factory = {'store': PostgresHistoryStore, 'provision-media': provision_empty_media_source,
               'provision-statements': provision_empty_statement_source}[backend]
    options=dict(history_schema='acl_history',checkpoint_schema='acl_checkpoint',
                 tenant='00000000-0000-0000-0000-000000000001',source='00000000-0000-0000-0000-000000000002')
    for changes in ({}, {'checkpoint_schema':'acl_history'}, {'tenant':'00000000-0000-0000-0000-000000000000'}):
        with pytest.raises(ValueError):
            factory('sqlite://',**{**options,**changes})


def test_first_owner_requires_verified_input_and_commit_guard():
    from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
    store=object.__new__(PostgresHistoryStore)
    for principal,genesis,guard in [('',b'genesis',lambda:None),('owner','not-bytes',lambda:None),('owner',b'',lambda:None),('owner',b'genesis',None)]:
        with pytest.raises(ValueError):
            store.enroll_first_media_owner(principal,genesis,before_commit=guard)


def test_provisioning_rejects_non_callable_guard_before_connecting(monkeypatch):
    from acl_service.infrastructure import postgres_media_provision as provision
    engine = Mock()
    monkeypatch.setattr(provision, 'create_engine', engine)
    with pytest.raises(ValueError, match='callable provisioning guard'):
        provision.provision_empty_media_source('postgresql+psycopg://unused',
            history_schema='acl_history', checkpoint_schema='acl_checkpoint',
            tenant='00000000-0000-0000-0000-000000000001',
            source='00000000-0000-0000-0000-000000000002', before_commit=False)
    engine.assert_not_called()


def test_statement_provisioning_creates_only_the_requested_protected_schemas(monkeypatch):
    from acl_service.infrastructure import postgres_media_provision as provision
    engine = MagicMock()
    engine.dialect.name = 'postgresql'
    connection = engine.begin.return_value.__enter__.return_value
    monkeypatch.setattr(provision, 'create_engine', lambda *args, **kwargs: engine)
    monkeypatch.setattr(provision, 'authority_digest', lambda db: b'checked-history')
    guard = Mock()
    provision.provision_empty_statement_source('postgresql+psycopg://unused',
        history_schema='acl_forum_history', checkpoint_schema='acl_forum_checkpoint',
        tenant='00000000-0000-0000-0000-000000000001',
        source='00000000-0000-0000-0000-000000000002', before_commit=guard)
    schema_commands = [x.args[0] for x in connection.exec_driver_sql.call_args_list]
    assert [sql for sql in schema_commands if sql.startswith('CREATE SCHEMA')] == [
        'CREATE SCHEMA "acl_forum_history"', 'CREATE SCHEMA "acl_forum_checkpoint"',
    ]
    sql = [str(x.args[0]) for x in connection.execute.call_args_list]
    assert any(query.startswith('CREATE TABLE statement_scopes') for query in sql)
    assert any(query.startswith('CREATE TABLE acl_forum_checkpoint.statement_checkpoints') for query in sql)
    assert not any('media_' in query or 'IF NOT EXISTS' in query for query in sql)
    assert guard.call_count == 2
    engine.dispose.assert_called_once()


def test_statement_runtime_checks_its_own_tables_without_ddl(monkeypatch):
    from acl_service.infrastructure import postgres_history_store as history
    engine = Mock()
    engine.dialect.name = 'postgresql'
    monkeypatch.setattr(history, 'create_engine', lambda *args, **kwargs: engine)
    tenant = '00000000-0000-0000-0000-000000000001'
    db = Mock()
    db.execute.return_value.fetchone.return_value = (tenant,)

    @contextmanager
    def transaction(_store, *, write, read_snapshot):
        assert write is False and read_snapshot is True
        yield db

    monkeypatch.setattr(history.PostgresHistoryStore, '_transaction', transaction)
    history.PostgresHistoryStore('postgresql+psycopg://unused',
        history_schema='acl_forum_history', checkpoint_schema='acl_forum_checkpoint',
        tenant=tenant, source='00000000-0000-0000-0000-000000000002',
        read_snapshot=True, statements=True)
    sql = [call.args[0] for call in db.execute.call_args_list]
    assert 'SELECT 1 FROM statement_scopes LIMIT 1' in sql
    assert 'SELECT 1 FROM freshness.statement_checkpoints LIMIT 1' in sql
    assert all(query.startswith('SELECT ') and 'media_' not in query for query in sql)
