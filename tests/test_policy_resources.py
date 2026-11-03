from importlib.resources import files
import casbin

def enforcer(name):
    model = casbin.Model()
    model.load_model_from_text(files('acl_service').joinpath('resources', name).read_text())
    return casbin.Enforcer(model)

def test_packaged_rbac_policy_enforces_role_and_resource():
    acl = enforcer('model_rbac.conf')
    acl.add_policy('seller', 'listing', 'create')
    acl.add_grouping_policy('alice', 'seller')
    assert acl.enforce('alice', 'listing', 'create')
    assert not acl.enforce('bob', 'listing', 'create')
    assert not acl.enforce('alice', 'other', 'create')

def test_packaged_abac_policy_requires_exact_constraint():
    acl = enforcer('model_abac.conf')
    acl.add_policy('*', 'inference', 'create', 'budget-ok')
    assert acl.enforce('alice', 'inference', 'create', 'budget-ok')
    assert not acl.enforce('alice', 'inference', 'create', 'budget-exceeded')
