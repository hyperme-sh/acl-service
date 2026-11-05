"""Run exactly the same storage contract against the real PostgreSQL adapter."""
import importlib.util
from pathlib import Path
import uuid
import pytest
from sqlalchemy import create_engine, text
from acl_service.infrastructure.policy_repo import PostgresPolicyStore

spec = importlib.util.spec_from_file_location('policy_contract', Path(__file__).parents[1] / 'tests' / 'policy_contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


@pytest.fixture
def tenants(migrated_sync_url):
    ids = uuid.uuid4(), uuid.uuid4()
    engine = create_engine(migrated_sync_url)
    try:
        with engine.begin() as cx:
            for tenant in ids:
                cx.execute(text('INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)'),
                           {'id': tenant, 'name': str(tenant)})
        yield ids
    finally:
        engine.dispose()


@pytest.fixture
def store(migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    try:
        yield PostgresPolicyStore(engine)
    finally:
        engine.dispose()


class TestPostgresPolicyStore(contract.PolicyStoreContract):
    pass
