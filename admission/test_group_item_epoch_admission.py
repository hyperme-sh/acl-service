"""Mock-only atomic group-item epoch admission and exact retry units."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from group_item_source import GroupItemSource
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict


class GroupItemEpochAdmissionTests(TestCase):
    def setUp(self):
        self.db=object();self.now=100;self.stop=False
        self.saved={'grants':[],'manifests':[],'finalizations':[], 'objectVersion':1}
        self.claims={'object':'media','owner':'owner','accessor':'owner','from':0,'until':8000000,
            'stated':1,'epoch':2,'grantRevision':2,'itemCiphertextDigest':'d'*64}
        self.snapshot={'objectSet':{'predicate':'same-group','setId':'set','stated':1,'hamState':1},'entries':[]}
        self.plan={'at':100,'fence':'f'*64,'grants':[self.claims],'snapshot':self.snapshot,
            'previousEpoch':1,'previousFinalizationId':'p'*64,'settleWindowMs':3600000}
        self.document={'manifest':{'object':'media','epoch':2,'previousEpoch':1,'revisionId':'r'*64,
            'keyCommitment':'k'*64,'settleWindowMs':3600000},'snapshot':self.snapshot}
        self.finalization={'object':'media','epoch':2,'previousEpoch':1,'previousFinalizationId':'p'*64,
            'revisionId':'r'*64,'candidateRevisionIds':['r'*64],'finalizationId':'z'*64}
        self.command={'grants':[{'claims':self.claims,'proof':{'signature':'signed'}}],
            'document':self.document,'finalization':self.finalization}
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner-key'}}}
        @contextmanager
        def transaction(*,write,before_commit):
            before=deepcopy(self.saved)
            try:yield self.db;before_commit()
            except BaseException:self.saved=before;raise
        def guard(at,cancel):
            if self.stop or not 0<=self.now-at<=4:raise HistoryConflict('expired or stopped')
            cancel()
        self.media=Mock(tenant='tenant',clock=lambda:self.now,native=[Mock() for _ in range(5)])
        self.media._guard.side_effect=guard
        self.media._load.side_effect=lambda *a:((1,b'n'*32,b'doc'),deepcopy(self.saved))
        self.media.identities.return_value=self.ids
        self.media._selected.return_value={'keyCommitment':'k'*64}
        self.media._history.side_effect=lambda object,doc,at,fin:{'object':object,'manifests':doc['manifests'],
            'finalizations':doc['finalizations'],'current':{'entries':[]}}
        self.media._save.side_effect=lambda db,object,row,doc:setattr(self,'saved',deepcopy(doc))
        for verifier in self.media.native:
            verifier.matches_grant.return_value=True;verifier.matches_manifest.return_value=True;verifier.verifies_history.return_value=True
        self.source=GroupItemSource(SimpleNamespace(media=self.media,store=SimpleNamespace(_transaction=transaction)))
        self.source._epoch_plan=Mock(side_effect=lambda *a:deepcopy(self.plan))

    def append(self,**changes):
        args=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set',at=100,fence='f'*64,payload=self.command)
        args.update(changes);return self.source.append_epoch(**args)

    def state(self,**changes):
        args=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set',payload=self.command)
        args.update(changes);return self.source.epoch_state(**args)

    def test_atomic_admission_keeps_all_signed_parts_and_current_group_window(self):
        self.assertEqual(self.state(),{'at':100,'state':'absent'})
        original=deepcopy(self.command);self.assertTrue(self.append())
        self.assertEqual(self.command,original)
        self.assertEqual(self.saved['grants'],[{**self.command['grants'][0],'ownerPub':'owner-key'}])
        self.assertEqual(self.saved['objectVersion'],2)
        self.assertEqual(self.saved['finalizations'][0]['seenAt'],100000)
        self.assertEqual(self.saved['groupItemEpochs'][0]['set'],'set')
        import json
        history=json.loads(self.media.native[4].verifies_history.call_args.args[0])
        self.assertEqual(history['current'],self.snapshot);self.assertEqual(history['groupWindowMs'],3600000)
        self.assertEqual(self.state(),{'at':100,'state':'applied'})

    def test_exact_retry_and_reconciliation_do_not_require_new_signatures(self):
        self.append();before=deepcopy(self.saved);self.source._epoch_plan.side_effect=AssertionError('must not prepare again')
        self.ids['bindings']['owner']['pub']='rotated'
        self.now=1000
        self.assertEqual(self.state()['state'],'applied')
        self.assertTrue(self.append(at=1000,fence='unused'))
        self.assertEqual(self.saved,before);self.assertEqual(self.media._save.call_count,1)
        self.assertEqual(self.state(set_id='other')['state'],'absent')

    def test_wrong_owner_tenant_and_changed_fence_refuse_without_write(self):
        for change in [{'tenant':'other'},{'owner':'other'},{'fence':'changed'},{'fence':None},{'at':95}]:
            with self.assertRaises((AdmissionRejected,HistoryConflict)):self.append(**change)
        self.media._save.assert_not_called()
        self.ids['owner']='other'
        with self.assertRaises(AdmissionRejected):self.state()

    def test_each_signed_component_and_ancestry_is_checked_before_save(self):
        for changed in ['claims','grant-proof','snapshot','previous','window','commitment','manifest','parent','epoch','revision','candidates','duplicate','history']:
            self.setUp()
            if changed=='claims':self.command['grants'][0]['claims']={**self.claims,'grantRevision':3}
            if changed=='grant-proof':self.media.native[0].matches_grant.return_value=False
            if changed=='snapshot':self.document['snapshot']={}
            if changed=='previous':self.document['manifest']['previousEpoch']=0
            if changed=='window':self.document['manifest']['settleWindowMs']=1
            if changed=='commitment':self.document['manifest']['keyCommitment']='changed'
            if changed=='manifest':self.media.native[2].matches_manifest.return_value=False
            if changed=='parent':self.finalization['previousFinalizationId']='other'
            if changed=='epoch':self.finalization['epoch']=3
            if changed=='revision':self.finalization['revisionId']='other'
            if changed=='candidates':self.finalization['candidateRevisionIds']=['other']
            if changed=='duplicate':self.saved['finalizations']=[{'proof':{'finalizationId':'z'*64}}]
            if changed=='history':self.media.native[4].verifies_history.return_value=False
            before=deepcopy(self.saved)
            with self.assertRaises((AdmissionRejected,HistoryConflict),msg=changed):self.append()
            self.assertEqual(self.saved,before);self.media._save.assert_not_called()

    def test_bounds_and_commit_abort_leave_no_partial_epoch(self):
        for bad in [None,{},[],{**self.command,'extra':1},{**self.command,'grants':[]},
                    {**self.command,'grants':[self.command['grants'][0]]*65},
                    {**self.command,'document':[]},{**self.command,'finalization':[]},
                    {**self.command,'document':{'padding':'x'*262144}},
                    {**self.command,'document':{'manifest':[]}}]:
            with self.assertRaises(AdmissionRejected):self.append(payload=bad)
        self.saved['groupItemEpochs']=[{'command':'other'}]*64
        with self.assertRaises(AdmissionRejected):self.append()
        self.saved['groupItemEpochs']=[];self.saved['objectVersion']=9007199254740991
        with self.assertRaises(AdmissionRejected):self.append()
        self.saved['objectVersion']=1;before=deepcopy(self.saved)
        def save(*args):self.saved=deepcopy(args[-1]);self.stop=True
        self.media._save.side_effect=save
        with self.assertRaises(HistoryConflict):self.append()
        self.assertEqual(self.saved,before)
