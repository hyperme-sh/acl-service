"""Pure SQL binding and source identifier unit checks; no database access."""
from unittest.mock import Mock

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


@pytest.mark.parametrize('backend', ['store', 'provision'])
def test_non_postgres_and_invalid_scopes_refuse_before_connecting(backend):
    from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
    from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source
    factory=PostgresHistoryStore if backend=='store' else provision_empty_media_source
    options=dict(history_schema='acl_history',checkpoint_schema='acl_checkpoint',
                 tenant='00000000-0000-0000-0000-000000000001',source='00000000-0000-0000-0000-000000000002')
    for changes in ({}, {'checkpoint_schema':'acl_history'}, {'tenant':'00000000-0000-0000-0000-000000000000'}):
        with pytest.raises(ValueError):
            factory('sqlite://',**{**options,**changes})
