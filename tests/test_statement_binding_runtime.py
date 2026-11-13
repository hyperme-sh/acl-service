"""Startup/storage contracts; execute in CI only."""
import json
import sqlite3
from contextlib import closing
from types import SimpleNamespace
from uuid import UUID
import pytest
from acl_service.infrastructure.statement_bindings import CONFIG_NAME, load_statement_bindings

TENANT = 'a5ed86d0-cb50-4404-a5ac-410aab086a82'


@pytest.fixture
def configured(tmp_path):
    history = tmp_path / 'history.db'; freshness = tmp_path / 'freshness.db'
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE statement_tenant (id INTEGER, tenant TEXT)')
        db.execute('INSERT INTO statement_tenant VALUES (1, ?)', (TENANT,))
        db.execute('CREATE TABLE statement_scopes (scope TEXT)')
        db.execute("INSERT INTO statement_scopes VALUES ('forum')")
    with closing(sqlite3.connect(freshness)) as db, db:
        db.execute('CREATE TABLE authority_checkpoint (id INTEGER, digest BLOB)')
        db.execute("INSERT INTO authority_checkpoint VALUES (1, x'01')")
        db.execute('CREATE TABLE statement_checkpoints (scope TEXT, digest BLOB)')
        db.execute("INSERT INTO statement_checkpoints VALUES ('forum', x'01')")
    rows = [dict(tenant=TENANT, subject=subject, scope='forum', historyFile=str(history), freshnessFile=str(freshness))
            for subject in ('service-one', 'service-two')]
    config = tmp_path / 'bindings.json'; config.write_text(json.dumps({'version': 1, 'bindings': rows}))
    for path in (config, history, freshness): path.chmod(0o600)
    return config, history, freshness, rows


def test_loads_only_exact_bindings_and_reuses_source(configured):
    config, _, _, _ = configured
    calls = []
    def factory(binding):
        calls.append(binding)
        return SimpleNamespace(tenant=TENANT, production_ready=True)
    bindings = load_statement_bindings({CONFIG_NAME: str(config)}, source_factory=factory)
    assert set(bindings) == {(UUID(TENANT), subject, 'forum') for subject in ('service-one', 'service-two')}
    assert len(calls) == 1
    assert bindings[(UUID(TENANT), 'service-one', 'forum')].source is bindings[(UUID(TENANT), 'service-two', 'forum')].source


@pytest.mark.parametrize('mutation', ['tenant', 'scope', 'authority', 'checkpoint', 'missing', 'public', 'alias'])
def test_unprovisioned_or_unsafe_store_cannot_construct_source(configured, mutation):
    config, history, freshness, _ = configured
    if mutation in ('tenant', 'scope'):
        with closing(sqlite3.connect(history)) as db, db:
            db.execute('DELETE FROM ' + ('statement_tenant' if mutation == 'tenant' else 'statement_scopes'))
    elif mutation in ('authority', 'checkpoint'):
        with closing(sqlite3.connect(freshness)) as db, db:
            db.execute('DELETE FROM ' + ('authority_checkpoint' if mutation == 'authority' else 'statement_checkpoints'))
    elif mutation == 'missing': history.unlink()
    elif mutation == 'public': history.chmod(0o644)
    else:
        freshness.unlink(); freshness.hardlink_to(history)
    calls = []
    with pytest.raises(RuntimeError, match='^Invalid statement source binding configuration$'):
        load_statement_bindings({CONFIG_NAME: str(config)}, source_factory=lambda binding: calls.append(binding))
    assert not calls
    if mutation == 'missing': assert not history.exists()


@pytest.mark.parametrize('source', [SimpleNamespace(tenant=TENANT, production_ready=False),
                                   SimpleNamespace(tenant='other', production_ready=True)])
def test_rejects_unprotected_or_cross_tenant_source(configured, source):
    config, _, _, _ = configured
    with pytest.raises(RuntimeError):
        load_statement_bindings({CONFIG_NAME: str(config)}, source_factory=lambda binding: source)


def test_application_factory_uses_configured_bindings(monkeypatch):
    from acl_service.app import create_app
    configured = {(UUID(TENANT), 'service', 'forum'): object()}
    monkeypatch.setattr('acl_service.infrastructure.statement_bindings.load_statement_bindings', lambda: configured)
    assert dict(create_app().state.statement_bindings) == configured
    assert dict(create_app(statement_bindings={}).state.statement_bindings) == {}
