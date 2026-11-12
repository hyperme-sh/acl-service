import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from acl_service.startup_identity import desired,plan
from acl_service._startup_contract import fingerprint
from acl_service.domain.policy_store import PolicyRecord


def fixture():
    c=json.loads((ROOT/'tests/fixtures/startup-identity.json').read_text())
    person={'schema_version':1,'mapping_sha256':fingerprint(c),'status':'bound','permissions':[],
        'person_id':'00000000-0000-4000-8000-000000000110','broker_subject':'opaque-person',
        'tenant_id':c['owner']['tenant_id'],'network_id':c['owner']['network_id'],
        'organizations':[{'slug':s,'id':o['organization_id'],'tenant_id':o['tenant_id'],'roles':o['roles']} for s,o in sorted(c['binding']['organizations'].items())]}
    return c,person


class StartupTests(unittest.TestCase):
    def test_separate_exact_grants_and_login_alias(self):
        c,p=fixture();marker,grants=desired(c,p)
        self.assertEqual(len(grants),9)
        self.assertEqual(len({tuple(rule) for kind,rule in grants if kind=='p'}),8)
        self.assertEqual(grants[-1],('g',['user:opaque-person',c['binding']['sea_public_key']]))
        self.assertFalse(any('keycloak' in str(rule) or '*' in str(rule) for _,rule in grants))

    def test_replay_and_unrelated_rows_untouched(self):
        c,p=fixture();other=PolicyRecord(1,'p','other','/unrelated','read')
        additions=plan(c,p,[other]);rows=[other]+[PolicyRecord(i+2,kind,*rule) for i,(kind,rule) in enumerate(additions)]
        self.assertEqual(plan(c,p,rows),[])
        self.assertEqual(rows[0],other)

    def test_conflicting_binding_and_revoked_grant_refuse_restoration(self):
        c,p=fixture();rows=[PolicyRecord(i+1,kind,*rule) for i,(kind,rule) in enumerate(plan(c,p,[]))]
        with self.assertRaises(ValueError):plan(c,p,rows[:-1])
        changed=dict(p,broker_subject='attacker')
        with self.assertRaises(ValueError):plan(c,changed,rows)

    def test_wrong_scope_or_unbound_identity_cannot_write(self):
        c,p=fixture()
        for key,value in [('status','reconciled'),('tenant_id','other'),('mapping_sha256','0'*64),('permissions',['admin']),('broker_subject',None),('organizations',[])]:
            with self.subTest(key=key),self.assertRaises(ValueError):desired(c,dict(p,**{key:value}))

    def test_exact_library_copy(self):
        record=json.loads((ROOT/'src/acl_service/startup_contract_source.json').read_text())
        self.assertEqual(record['sha256'],hashlib.sha256((ROOT/'src/acl_service/_startup_contract.py').read_bytes()).hexdigest())

    def test_enforcer_keeps_company_and_platform_resources_distinct(self):
        from acl_service.infrastructure.enforcer_factory import enforce_rbac
        c,p=fixture()
        rows=[PolicyRecord(i+1,kind,*rule) for i,(kind,rule) in enumerate(plan(c,p,[]))]
        class Store:
            def list_rules(self,tenant):return rows if str(tenant)==c['owner']['tenant_id'] else []
        from uuid import UUID
        store=Store();tenant=UUID(c['owner']['tenant_id'])
        for org in p['organizations']:
            self.assertTrue(enforce_rbac(store,tenant,'user:'+p['broker_subject'],'/organizations/'+org['id'],'admin'))
            self.assertFalse(enforce_rbac(store,tenant,'other-company-member','/organizations/'+org['id'],'admin'))
        self.assertFalse(enforce_rbac(store,tenant,'user:'+p['broker_subject'],'/keycloak','admin'))
        self.assertFalse(enforce_rbac(store,tenant,'user:'+p['broker_subject'],'/platform/spanopticon','owner'))
        self.assertFalse(enforce_rbac(store,UUID('00000000-0000-4000-8000-000000000999'),p['broker_subject'],'/platform/spanopticon','admin'))


class ExplicitGrantTests(unittest.TestCase):
    def test_admin_booleans_and_each_declared_role_are_independent(self):
        from acl_service._startup_contract import binding_fingerprint
        c,p=fixture()
        c['binding']['platform_admin']={'spanopticon':False,'hyperme.sh':True}
        c['binding']['organizations']['fyberlabs']['roles']=['owner']
        c['binding_sha256']=binding_fingerprint(c['binding'])
        p['mapping_sha256']=fingerprint(c)
        p['organizations'][0]['roles']=['owner']
        _,grants=desired(c,p)
        self.assertNotIn(('p',[c['binding']['sea_public_key'],'/platform/spanopticon','admin']),grants)
        self.assertNotIn(('p',[c['binding']['sea_public_key'],'/organizations/'+p['organizations'][0]['id'],'admin']),grants)
        self.assertIn(('p',[c['binding']['sea_public_key'],'/platform/hyperme.sh','admin']),grants)

    def test_peer_cannot_replace_a_declared_organization_id(self):
        c,p=fixture();p['organizations'][0]['id']='00000000-0000-4000-8000-000000009999'
        with self.assertRaises(ValueError):desired(c,p)

    def test_login_alias_respects_storage_width(self):
        c,p=fixture();p['broker_subject']='s'*250
        self.assertEqual(len(desired(c,p)[1][-1][1][0]),255)
        p['broker_subject']='s'*251
        with self.assertRaises(ValueError):desired(c,p)
