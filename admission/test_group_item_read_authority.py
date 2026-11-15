"""Mock-only current group item authorization and commit race units."""
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock,patch
from group_item_source import GroupItemSource
from group_item_grants import grant_key
from statement_source import encoded
from acl_service.domain.group_wrap import GroupKeyReadPermit
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict

class GroupItemReadAuthorityTests(TestCase):
    def setUp(self):
        self.now=100;self.db=object();self.row=(1,b'n'*32,b'doc')
        self.claims={'object':'media','owner':'owner','accessor':'reader','from':0,'until':9000000,
            'stated':1,'epoch':2,'grantRevision':1,'itemCiphertextDigest':'d'*64}
        self.grant={'predicate':'same-group','set':'set','claims':self.claims,'proof':{'sig':'signed'}}
        self.wrap={'digest':'c'*64,'length':24,'itemEpoch':2,'itemRevisionId':'a'*64,'itemDigest':'d'*64,
            'groupEpoch':3,'groupRevisionId':'e'*64,'groupKeyCommitment':'f'*64}
        self.doc={'floor':1,'policyUntil':9000,'objectVersion':4,
            'groupItemGrants':{'rows':[self.grant],'frozen':[],'conflicts':[]},
            'finalizations':[{'proof':{'epoch':2,'revisionId':'a'*64}}],
            'manifests':[{'document':{'manifest':{'epoch':2,'revisionId':'a'*64,'aclSnapshot':'b'*64}}}],
            'groupItemEpochs':[{'predicate':'same-group','set':'set','epoch':2,'revisionId':'a'*64}],
            'groupItemStatuses':{grant_key('same-group','set','reader'):{'signedAt':100000,'maxAgeMs':60000}},
            'groupItemWraps':{encoded(['same-group','set']).decode('ascii'):self.wrap}}
        self.ids={'owner':'owner','bindings':{who:{'pub':who,'head':who} for who in ['owner','reader']}}
        self.projection={'predicate':'same-group','set':'set','members':['reader'],
            'snapshot':{'objectSet':{},'members':[{'accessor':'reader','stated':1,'hamState':2}]}}
        self.current=({'policyUntil':9000},{},{'settleWindowMs':3600000})
        @contextmanager
        def transaction(*,write,before_commit):yield self.db;before_commit()
        self.store=SimpleNamespace(_transaction=transaction,_observe_floor=Mock())
        self.media=Mock(tenant='tenant',clock=lambda:self.now,native=[Mock() for _ in range(5)])
        self.media._load.side_effect=lambda *a:(self.row,self.doc)
        self.media.identities.return_value=self.ids;self.media._snapshot.return_value={'entries':[]}
        self.media._history.return_value={}
        self.media.native[0].matches_grant.return_value=True
        self.media.native[1].matches_status.return_value=True
        self.media.native[3].matches_settled.return_value=True
        self.key=GroupKeyReadPermit('tenant','reader','same-group','set',3,'e'*64,'epub','f'*64,'1'*64,102)
        self.keys=SimpleNamespace(media=self.media,store=self.store,_read_permit=Mock(side_effect=lambda *a:self.key))
        self.source=GroupItemSource(self.keys)
        self.source._authority=Mock(side_effect=lambda *a:({'projection':self.projection},self.row,self.doc,self.ids,self.current))
        patcher=patch('acl_service.infrastructure.authority_checkpoint.authority_digest',return_value=b'digest')
        self.digest=patcher.start();self.addCleanup(patcher.stop)

    def permit(self,**changes):
        args=dict(tenant='tenant',reader='reader',object='media',predicate='same-group',set_id='set');args.update(changes)
        return self.source.authorize_read(**args)

    def test_commit_after_clock_tick_and_floor_observation(self):
        permit=self.permit();self.now=101
        self.assertTrue(self.source.commit_read(permit));self.assertEqual(self.doc['floor'],2)
        self.assertEqual(self.store._observe_floor.call_count,2);self.media._save.assert_called_once()
        self.media._save.reset_mock();self.assertTrue(self.source.commit_read(permit));self.media._save.assert_not_called()

    def test_missing_and_changed_authorities_refuse(self):
        for case in ['tenant','scope','detached','missing','frozen','identity','owner','cancelled','future','expired',
            'signature','membership','member-cancel','members','direct','epoch','history','record','status','status-proof','wrap','expiry']:
            with self.subTest(case=case):
                self.setUp();args={}
                if case=='tenant':args['tenant']='other'
                if case=='scope':args['set_id']='other'
                if case=='detached':self.current=None
                if case=='missing':self.doc['groupItemGrants']['rows']=[]
                if case=='frozen':self.doc['groupItemGrants']['frozen']=[grant_key('same-group','set','reader')]
                if case=='identity':del self.ids['bindings']['reader']
                if case=='owner':self.claims['owner']='other'
                if case=='cancelled':self.claims['stated']=0
                if case=='future':self.claims['from']=100001
                if case=='expired':self.claims['until']=100000
                if case=='signature':self.media.native[0].matches_grant.return_value=False
                if case=='membership':self.projection['snapshot']['members']=[]
                if case=='member-cancel':self.projection['snapshot']['members'][0]['stated']=0
                if case=='members':self.projection['members']=[]
                if case=='direct':self.media._snapshot.return_value={'entries':[{'accessor':'reader','scope':'direct','stated':1,'from':0,'until':9000000}]}
                if case=='epoch':self.claims['epoch']=1
                if case=='history':self.media.native[3].matches_settled.return_value=False
                if case=='record':self.doc['groupItemEpochs']=[]
                if case=='status':self.doc['groupItemStatuses']={}
                if case=='status-proof':self.media.native[1].matches_status.return_value=False
                if case=='wrap':self.doc['groupItemWraps']={}
                if case=='expiry':self.key=replace(self.key,expires_at=100)
                with self.assertRaises(AdmissionRejected):self.permit(**args)
                self.media._save.assert_not_called()

    def test_metadata_bounds_and_epoch_bindings(self):
        for field,bad in [('length',True),('length',0),('length',65537),('itemEpoch',True),('groupEpoch',False),
            ('itemEpoch',9007199254740992),('digest','G'*64),('itemRevisionId','b'*64),('itemDigest','a'*64),
            ('groupEpoch',2),('groupRevisionId','a'*64),('groupKeyCommitment','a'*64),('extra',1)]:
            with self.subTest(field=field,bad=bad):
                self.setUp();self.wrap[field]=bad
                with self.assertRaises(AdmissionRejected):self.permit()

    def test_commit_rechecks_races_before_floor_write(self):
        for case in ['row','authority','key','scope','expired','cancelled']:
            with self.subTest(case=case):
                self.setUp();permit=self.permit()
                if case=='row':self.row=(2,b'n'*32,b'changed')
                if case=='authority':self.digest.return_value=b'changed'
                if case=='key':self.key=replace(self.key,fence='2'*64)
                if case=='scope':self.projection['set']='other'
                if case=='expired':self.now=102
                if case=='cancelled':self.claims['stated']=0
                with self.assertRaises((AdmissionRejected,HistoryConflict)):self.source.commit_read(permit)
                self.media._save.assert_not_called();self.store._observe_floor.assert_not_called()
        self.setUp()
        for bad in [None,{},replace(self.permit(),key=None)]:
            with self.assertRaises(AdmissionRejected):self.source.commit_read(bad)

    def test_snapshot_precedence_cancellations_and_capacity(self):
        direct={'accessor':'reader','scope':'direct','stated':0,'from':0,'until':9000000}
        self.media._snapshot.return_value={'entries':[direct]}
        self.assertEqual(self.source._read_snapshot(self.doc,self.ids,self.projection,100)['entries'][0]['scope'],'same-group')
        self.claims['stated']=0
        self.assertEqual(self.source._read_snapshot(self.doc,self.ids,self.projection,100)['entries'],[direct])
        self.media._snapshot.return_value={'entries':[]};self.projection['snapshot']['members']=[]
        self.assertEqual(self.source._read_snapshot(self.doc,self.ids,self.projection,100)['entries'][0]['hamState'],0)
        self.claims['stated']=1;self.projection['snapshot']['members']=[{'accessor':'reader','stated':1,'hamState':2}]
        self.media.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.source._read_snapshot(self.doc,self.ids,self.projection,100)
        self.media.native[0].matches_grant.return_value=True
        self.media._snapshot.return_value={'entries':[{'accessor':str(i)} for i in range(64)]}
        with self.assertRaises(AdmissionRejected):self.source._read_snapshot(self.doc,self.ids,self.projection,100)
