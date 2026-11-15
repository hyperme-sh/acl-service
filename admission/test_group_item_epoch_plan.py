"""Pure mock units for a complete next item epoch plan; no native/DB execution."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from group_item_source import GroupItemSource
from acl_service.domain.history_store import AdmissionRejected


class GroupItemEpochPlanTests(TestCase):
    def setUp(self):
        self.db=object()
        @contextmanager
        def transaction(*,write,before_commit):
            self.assertFalse(write);yield self.db;before_commit()
        self.claims={'object':'media','owner':'owner','accessor':'owner','from':0,'until':8000000,
            'stated':1,'epoch':1,'grantRevision':1,'itemCiphertextDigest':'d'*64}
        self.owner={'claims':dict(self.claims),'proof':{'sig':'owner'}}
        self.reader={'predicate':'same-group','set':'set','claims':{**self.claims,'accessor':'reader','epoch':2},'proof':{'sig':'reader'}}
        self.doc={'grants':[self.owner],'frozen':[],'manifests':[{'document':{'manifest':{'epoch':1,'revisionId':'r','keyCommitment':'k'*64}}}],'finalizations':[],'policyUntil':9000,
            'groupItemGrants':{'rows':[self.reader],'frozen':[],'conflicts':[]},'wraps':{'owner':{'itemDigest':'d'*64}}}
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'key','epub':'owner-e'},'reader':{'pub':'reader-k','epub':'reader-e'}}}
        self.projection={'predicate':'same-group','set':'set','members':['owner','reader'],
            'snapshot':{'objectSet':{'predicate':'same-group','setId':'set','stated':1,'hamState':3},
                'members':[{'accessor':who,'stated':1,'hamState':2} for who in ['owner','reader']]}}
        self.group={'policyUntil':9000};self.config={'settleWindowMs':3600000}
        self.view={'fence':'authority','projection':self.projection}
        self.item=SimpleNamespace(epoch=1,fence='item')
        self.media=Mock(tenant='tenant',clock=lambda:100,native=[Mock()])
        self.media.native[0].matches_grant.return_value=True
        self.media._permit.return_value=(self.item,self.ids,None,self.doc)
        self.media._selected_finalization.return_value={'epoch':1,'revisionId':'r','finalizationId':'parent'}
        self.media._fence.return_value='media-fence'
        self.media._latest.side_effect=lambda doc:{r['claims']['accessor']:r for r in doc['grants']}
        self.source=GroupItemSource(SimpleNamespace(media=self.media,store=SimpleNamespace(_transaction=transaction)))
        self.source._authority=Mock(side_effect=lambda *args:(self.view,(1,b'n'*32,b'doc'),self.doc,self.ids,(self.group,{},self.config)))

    def plan(self,**changes):
        args=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set');args.update(changes)
        return self.source.epoch_view(**args)

    def test_plan_refreshes_only_direct_grants_and_keeps_group_scope(self):
        original=deepcopy(self.doc);plan=self.plan()
        self.assertEqual(plan['grants'],[{**self.claims,'epoch':2,'grantRevision':2}])
        self.assertEqual(plan['groupReaders'],['reader']);self.assertEqual(set(plan['bindings']),{'owner'})
        self.assertEqual([(e['accessor'],e['scope'],e['hamState']) for e in plan['snapshot']['entries']],
            [('owner','direct',0),('reader','same-group',2)])
        self.assertEqual(plan['snapshot']['objectSet'],self.projection['snapshot']['objectSet'])
        self.assertEqual(self.doc,original);self.media._save.assert_not_called()
        self.view['fence']='changed';self.assertNotEqual(plan['fence'],self.plan()['fence'])
        plan['bindings']['owner']['pub']='mutated';self.assertEqual(self.ids['bindings']['owner']['pub'],'key')

    def test_overlapping_direct_access_survives_group_cancellation(self):
        self.doc['grants'].append({'claims':{**self.claims,'accessor':'reader','grantRevision':7},'proof':{}})
        for stated in [1,0]:
            self.reader['claims']['stated']=stated;plan=self.plan()
            self.assertEqual(plan['groupReaders'],[])
            reader=next(e for e in plan['snapshot']['entries'] if e['accessor']=='reader')
            self.assertEqual((reader['scope'],reader['stated'],reader['grantRevision']),('direct',1,8))
        self.doc['grants'][-1]['claims']['stated']=0;self.reader['claims']['stated']=1
        reader=next(e for e in self.plan()['snapshot']['entries'] if e['accessor']=='reader')
        self.assertEqual((reader['scope'],reader['stated']),('same-group',1))

    def test_missing_or_cancelled_membership_and_forked_grants_cannot_be_live(self):
        for change in ['member','missing','frozen','private','expired']:
            self.setUp()
            if change=='member':self.projection['snapshot']['members'][1]['stated']=0
            if change=='missing':self.projection['snapshot']['members']=[];self.projection['members']=[]
            if change=='frozen':self.doc['groupItemGrants']['frozen']=['["same-group","set","reader"]']
            if change=='private':self.reader['claims']['stated']=0
            if change=='expired':self.reader['claims']['until']=50000
            plan=self.plan();self.assertEqual(plan['groupReaders'],[])
            self.assertEqual(plan['snapshot']['entries'][1]['stated'],0)

    def test_wrong_scope_epoch_identity_signature_or_digest_refuses(self):
        for field,value in [('epoch',3),('itemCiphertextDigest','x'*64),('owner','other'),('until',200000),('until',10000000)]:
            self.setUp();self.reader['claims'][field]=value
            with self.assertRaises(AdmissionRejected):self.plan()
        self.setUp();self.ids['bindings'].pop('reader')
        with self.assertRaises(AdmissionRejected):self.plan()
        self.setUp();self.media.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.plan()
        self.setUp()
        for changes in [{'tenant':'other'},{'set_id':'other'}]:
            with self.assertRaises(AdmissionRejected):self.plan(**changes)
        self.source._authority.return_value=None;self.source._authority.side_effect=lambda *a:(self.view,None,None,None,None)
        with self.assertRaises(AdmissionRejected):self.plan()

    def test_expired_direct_recipient_gets_a_signed_cancellation_not_a_live_expired_row(self):
        self.doc['grants'].append({'claims':{**self.claims,'accessor':'old','until':50000},'proof':{}})
        plan=self.plan();draft=next(d for d in plan['grants'] if d['accessor']=='old')
        self.assertEqual((draft['stated'],draft['grantRevision'],draft['epoch']),(0,2,2))
        self.assertNotIn('old',plan['bindings'])

    def test_direct_window_capacity_and_epoch_exhaustion_refuse(self):
        for change in ['frozen','identity','future','digest','owner','revision','window','epochs','grants','parent','floor','owner-cancel']:
            self.setUp()
            if change=='frozen':self.doc['frozen']=['owner']
            if change=='identity':self.ids['bindings'].pop('reader');self.owner['claims']['accessor']='reader'
            if change=='future':self.owner['claims']['from']=200000
            if change=='digest':self.owner['claims']['itemCiphertextDigest']='other'
            if change=='owner':self.owner['claims']['owner']='other'
            if change=='revision':self.owner['claims']['grantRevision']=9007199254740991
            if change=='window':self.owner['claims']['until']=200000
            if change=='epochs':self.doc['manifests']=[{}]*64
            if change=='grants':self.doc['grants']=[self.owner]*64
            if change=='parent':self.media._selected_finalization.return_value={'epoch':2,'finalizationId':'parent'}
            if change=='floor':self.item.epoch=9007199254740991;self.media._selected_finalization.return_value={'epoch':self.item.epoch,'finalizationId':'parent'}
            if change=='owner-cancel':self.owner['claims']['stated']=0
            with self.assertRaises(AdmissionRejected,msg=change):self.plan()

    def test_policy_expiry_rejects_and_direct_window_only_attenuates(self):
        self.doc['policyUntil']=7000
        self.reader['claims']['until']=7000000
        plan=self.plan()
        self.assertEqual(plan['grants'][0]['until'],7000000)
        self.assertEqual(self.owner['claims']['until'],8000000)
        for where in [self.doc,self.group]:
            where['policyUntil']=200
            with self.assertRaises(AdmissionRejected):self.plan()
            where['policyUntil']=9000
        self.doc['grants'].append({'claims':{**self.claims,'accessor':'old','until':50000,'grantRevision':9007199254740991},'proof':{}})
        with self.assertRaises(AdmissionRejected):self.plan()


    def test_maintenance_preparation_does_not_require_read_status_or_release_keys(self):
        self.media._permit.side_effect=AssertionError('read authority must not be requested')
        self.doc['statuses']={}
        plan=self.plan()
        self.assertEqual(plan['keyCommitment'],'k'*64)
        self.assertNotIn('wrap',plan);self.assertNotIn('payload',plan)
        self.media._save.assert_not_called()
        self.media._selected_finalization.assert_called_with('media',self.doc,100,historical=True,db=self.db)
        original=plan['fence'];self.media._fence.return_value='changed'
        self.assertNotEqual(self.plan()['fence'],original)

    def test_maintenance_requires_current_owner_and_authentic_parent(self):
        for case in ['tenant','owner','binding','manifest','wrap','object','expired']:
            self.setUp();tenant='tenant';owner='owner'
            if case=='tenant':tenant='other'
            if case=='owner':owner='reader'
            if case=='binding':del self.ids['bindings']['owner']
            if case=='manifest':self.doc['manifests']=[]
            if case=='wrap':self.doc['wraps']={}
            if case=='object':self.owner['claims']['object']='other'
            if case=='expired':self.owner['claims']['until']=100000
            with self.assertRaises(AdmissionRejected):self.source._maintenance_parent(self.db,tenant,owner,'media',(1,b'n'*32,b'doc'),self.doc,self.ids,100)
