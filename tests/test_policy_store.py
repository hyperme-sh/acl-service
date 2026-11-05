from threading import RLock
from uuid import uuid4
import pytest
from acl_service.domain.policy_store import PolicyRecord
from acl_service.infrastructure.enforcer_factory import enforce_rbac
from policy_contract import PolicyStoreContract


class MemoryPolicyStore:
    """Test adapter, deliberately independent of SQLAlchemy and database models."""
    def __init__(self):
        self.rows = {}
        self.lock = RLock()
        self.next_id = 1

    def list_rules(self, tenant_id):
        with self.lock:
            return [row for (tenant, _, _), row in self.rows.items() if tenant == tenant_id]

    def add_rule(self, tenant_id, ptype, rule):
        with self.lock:
            key = (tenant_id, ptype, tuple(rule))
            if key not in self.rows:
                self.rows[key] = PolicyRecord(self.next_id, ptype, *rule)
                self.next_id += 1
            return self.rows[key]

    def add_rule_if_absent(self, tenant_id, ptype, rule):
        with self.lock:
            if (tenant_id, ptype, tuple(rule)) in self.rows:
                return False
            self.add_rule(tenant_id, ptype, rule)
            return True

    def delete_rule(self, tenant_id, ptype, rule):
        with self.lock:
            return self.rows.pop((tenant_id, ptype, tuple(rule)), None) is not None


@pytest.fixture
def store():
    return MemoryPolicyStore()


@pytest.fixture
def tenants():
    return uuid4(), uuid4()


class TestMemoryPolicyStore(PolicyStoreContract):
    pass


def test_storage_failure_cannot_become_an_allow():
    class BrokenStore:
        def list_rules(self, tenant_id):
            raise RuntimeError('storage unavailable')
    with pytest.raises(RuntimeError, match='storage unavailable'):
        enforce_rbac(BrokenStore(), uuid4(), 'alice', 'resource', 'read')
