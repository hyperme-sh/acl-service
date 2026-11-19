from contextlib import contextmanager
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from acl_service.domain.history_store import AdmissionRejected
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
    def transaction(*, write):
        assert not write
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
