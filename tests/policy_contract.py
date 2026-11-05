"""Shared behavioral checks for every policy storage adapter."""
from acl_service.domain.policy_store import PolicyRecord
from acl_service.infrastructure.enforcer_factory import enforce_rbac, enforce_abac


class PolicyStoreContract:
    def test_tenant_isolation_and_redelivery(self, store, tenants):
        a, b = tenants
        rule = ['alice', 'resource', 'read']
        assert store.add_rule_if_absent(a, 'p', rule)
        assert not store.add_rule_if_absent(a, 'p', rule)
        assert store.list_rules(b) == []
        row = store.add_rule(a, 'p', rule)
        assert isinstance(row, PolicyRecord)
        assert store.list_rules(a) == [row]
        assert store.add_rule(b, 'p', rule)
        assert store.delete_rule(a, 'p', rule)
        assert store.list_rules(a) == []
        assert len(store.list_rules(b)) == 1

    def test_exact_delete_preserves_other_model_and_revokes_immediately(self, store, tenants):
        a, _ = tenants
        rbac = ['alice', 'resource', 'read']
        abac = [*rbac, 'budget']
        store.add_rule(a, 'p', abac)
        assert not store.delete_rule(a, 'p', rbac)
        store.add_rule(a, 'p', rbac)
        assert enforce_rbac(store, a, *rbac)
        assert enforce_abac(store, a, *abac)
        assert store.delete_rule(a, 'p', rbac)
        assert not enforce_rbac(store, a, *rbac)
        assert enforce_abac(store, a, *abac)
        assert not store.delete_rule(a, 'p', rbac)

    def test_role_and_literal_values(self, store, tenants):
        a, b = tenants
        store.add_rule(a, 'p', ['reader', 'resource,with,commas', 'read'])
        store.add_rule(a, 'g', ['alice', 'reader'])
        assert enforce_rbac(store, a, 'alice', 'resource,with,commas', 'read')
        assert not enforce_rbac(store, b, 'alice', 'resource,with,commas', 'read')
