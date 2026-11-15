"""Pure mock combined selection units; no DB, HTTP or native execution."""
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock,patch
from media_source import MediaSource
from acl_service.domain.history_store import AdmissionRejected

class CombinedSelectionTests(TestCase):
    def setUp(self):
        self.db=object();self.source=object.__new__(MediaSource);self.source.tenant='tenant'
        self.source.native=[Mock() for _ in range(5)]
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner'},'reader':{'pub':'reader','epub':'epub'}}}
        self.source.identities=Mock(return_value=self.ids)
        self.claims={'object':'media','owner':'owner','accessor':'reader','from':0,'until':9000000,'stated':1,'epoch':2,'grantRevision':2,'itemCiphertextDigest':'d'*64}
        self.doc={'floor':1,'anchor':'anchor','objectVersion':4,'policyUntil':9000,'frozen':[],
            'grants':[{'claims':self.claims,'proof':{}}],
            'finalizations':[{'proof':{'epoch':i,'revisionId':str(i)*64}} for i in (1,2)],
            'manifests':[{'document':{'manifest':{'epoch':i,'revisionId':str(i)*64,'aclSnapshot':'a'*64},'snapshot':{'retained':i}}} for i in (1,2)],
            'groupItemEpochs':[{'epoch':2,'revisionId':'2'*64,'predicate':'same-group','set':'set','settleWindowMs':3600000}],
            'statuses':{'reader':{'signedAt':100000,'maxAgeMs':60000}},
            'wraps':{'reader':{'epoch':2,'revisionId':'2'*64,'readerEpub':'epub','itemDigest':'d'*64,'record':'r','digest':'d'}}}
        self.source._load=Mock(return_value=((1,b'n'*32,b'doc'),self.doc))
        self.snapshot={'entries':[{'accessor':'reader','scope':'direct'}],'objectSet':{'stated':1}}
        self.source._combined_current=Mock(return_value=(self.snapshot,3600000,'group-checkpoint'))
        for native in self.source.native:
            native.matches_settled.return_value=True;native.matches_grant.return_value=True;native.matches_status.return_value=True
        patcher=patch('media_source.authority_digest',return_value=b'checkpoint');patcher.start();self.addCleanup(patcher.stop)

    def test_current_selection_uses_complete_snapshot_and_recorded_historical_window(self):
        self.assertEqual(self.source._selected('media',self.doc,100,db=self.db)['epoch'],2)
        history=json.loads(self.source.native[3].matches_settled.call_args.args[0])
        self.assertEqual(history['current'],self.snapshot);self.assertEqual(history['groupWindowMs'],3600000)
        self.source._combined_current.reset_mock()
        self.source._selected_finalization('media',self.doc,100,historical=True)
        history=json.loads(self.source.native[3].matches_settled.call_args.args[0])
        self.assertEqual(history['current'],{'retained':2});self.assertEqual(history['groupWindowMs'],3600000)
        self.source._combined_current.assert_not_called()

    def test_stale_combined_history_never_falls_back_to_older_direct_epoch(self):
        self.source.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):self.source._selected('media',self.doc,100,db=self.db)
        self.assertEqual(self.source.native[3].matches_settled.call_count,1)
        self.doc['groupItemEpochs']=[]
        self.source.native[3].matches_settled.return_value=True
        self.assertEqual(self.source._selected('media',self.doc,100)['epoch'],2)
        self.source._selected_finalization('media',self.doc,100,historical=True)
        history=json.loads(self.source.native[3].matches_settled.call_args.args[0]);self.assertNotIn('groupWindowMs',history)

    def test_direct_read_still_needs_independent_grant_status_wrap_and_group_checkpoint(self):
        permit=self.source._permit(self.db,'tenant','reader','media',100)[0]
        self.assertEqual(permit.epoch,2)
        self.source._combined_current.return_value=(self.snapshot,3600000,'changed-checkpoint')
        changed=self.source._permit(self.db,'tenant','reader','media',101,102)[0]
        self.assertNotEqual(changed.fence,permit.fence)
        for case in ['grant','status','wrap','membership']:
            self.setUp()
            if case=='grant':self.source.native[0].matches_grant.return_value=False
            if case=='status':self.source.native[1].matches_status.return_value=False
            if case=='wrap':self.doc['wraps']['reader']['epoch']=1
            if case=='membership':self.source._combined_current.side_effect=AdmissionRejected('changed')
            with self.assertRaises(AdmissionRejected):self.source._permit(self.db,'tenant','reader','media',100)

    def test_complete_projection_stays_inside_the_existing_transaction(self):
        with patch('group_source.GroupSource') as groups,patch('group_key_source.GroupKeySource') as keys,patch('group_item_source.GroupItemSource') as items:
            item=items.return_value;item.keys=keys.return_value
            projection={'predicate':'same-group','set':'set'}
            item._authority.return_value=({'projection':projection},None,self.doc,self.ids,({}, {}, {'settleWindowMs':3600000}))
            item._read_snapshot.return_value=self.snapshot;item.keys._load_current.return_value=('held',{}, {}, {})
            item.keys._fence.return_value='stable-checkpoint'
            result=MediaSource._combined_current(self.source,self.db,'media',self.doc,100)
            self.assertEqual(result,(self.snapshot,3600000,'stable-checkpoint'))
            groups.assert_called_once_with(self.source,transaction=self.db)
            item.keys._fence.assert_called_once_with(self.db,'held',0,'same-group','set')
            item._authority.return_value=({'projection':projection},None,self.doc,self.ids,None)
            with self.assertRaises(AdmissionRejected):MediaSource._combined_current(self.source,self.db,'media',self.doc,100)
            with self.assertRaises(AdmissionRejected):MediaSource._combined_current(self.source,None,'media',self.doc,100)
            groups.side_effect=ValueError('unsupported source')
            with self.assertRaises(AdmissionRejected):MediaSource._combined_current(self.source,self.db,'media',self.doc,100)


    def test_detached_current_snapshot_never_loads_independent_group_members(self):
        with patch('group_source.GroupSource'),patch('group_key_source.GroupKeySource'),patch('group_item_source.GroupItemSource') as items:
            item=items.return_value;projection={'predicate':'same-group','set':'set','snapshot':{'objectSet':{'stated':0}}}
            item._authority.return_value=({'projection':projection},'row',self.doc,self.ids,None)
            item._read_snapshot.return_value={'entries':[],'objectSet':{'stated':0}}
            self.source._fence=Mock(return_value='media-only-fence')
            result=MediaSource._combined_current(self.source,self.db,'media',self.doc,100)
            self.assertEqual(result,({'entries':[],'objectSet':{'stated':0}},3600000,'media-only-fence'))
            item.keys._load_current.assert_not_called()
            self.doc['groupItemEpochs']=[]
            with self.assertRaises(AdmissionRejected):MediaSource._combined_current(self.source,self.db,'media',self.doc,100)
