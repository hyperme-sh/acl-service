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


def test_startup_grants_concurrent_replay_and_conflict(store,tenants):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from acl_service._startup_contract import fingerprint,binding_fingerprint
    from acl_service.infrastructure.enforcer_factory import enforce_rbac
    c=json.loads((Path(__file__).parents[1]/'tests/fixtures/startup-identity.json').read_text())
    c['owner']['tenant_id']=str(tenants[0])
    for org in c['binding']['organizations'].values():org['tenant_id']=str(tenants[0])
    c['binding_sha256']=binding_fingerprint(c['binding'])
    person={'schema_version':1,'mapping_sha256':fingerprint(c),'status':'bound','permissions':[],
        'person_id':str(uuid.uuid4()),'broker_subject':'startup-'+uuid.uuid4().hex,
        'tenant_id':c['owner']['tenant_id'],'network_id':c['owner']['network_id'],
        'organizations':[{'slug':slug,'id':org['organization_id'],'tenant_id':org['tenant_id'],'roles':org['roles']} for slug,org in sorted(c['binding']['organizations'].items())]}
    store.add_rule(tenants[0],'p',['unrelated','/unchanged','read'])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:store.reconcile_startup(c,person),range(8)))
    assert all(result==results[0] for result in results)
    assert len(store.list_rules(tenants[0]))==11
    assert len(store.list_rules(tenants[1]))==0
    for org in person['organizations']:
        assert enforce_rbac(store,tenants[0],'user:'+person['broker_subject'],'/organizations/'+org['id'],'admin')
    assert not enforce_rbac(store,tenants[0],'user:'+person['broker_subject'],'/keycloak','admin')
    before=store.list_rules(tenants[0])
    with pytest.raises(ValueError):store.reconcile_startup(c,dict(person,broker_subject='attacker'))
    assert store.list_rules(tenants[0])==before
    # Fail during flush: transaction rollback leaves no partial grants.
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    import copy
    c2=copy.deepcopy(c);c2['owner']['tenant_id']=str(tenants[1])
    for org in c2['binding']['organizations'].values():org['tenant_id']=str(tenants[1])
    c2['binding_sha256']=binding_fingerprint(c2['binding'])
    p2=copy.deepcopy(person);p2.update(tenant_id=str(tenants[1]),mapping_sha256=fingerprint(c2))
    for org in p2['organizations']:org['tenant_id']=str(tenants[1])
    def interrupt(*args):raise RuntimeError('interrupted flush')
    event.listen(Session,'before_flush',interrupt)
    try:
        with pytest.raises(RuntimeError,match='interrupted'):store.reconcile_startup(c2,p2)
    finally:event.remove(Session,'before_flush',interrupt)
    assert store.list_rules(tenants[1])==[]
    assert store.reconcile_startup(c2,p2)['status']=='reconciled'
