"""Pure mock owner maintenance permit units; no storage or native calls."""
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock,patch
from group_owner_wrap_source import GroupOwnerWrapSource
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict

class OwnerWrapTests(TestCase):
    def setUp(self):
        self.now=100;self.db=object();self.row=(1,b'n'*32,b'doc')
        @contextmanager
        def transaction(*,write,before_commit):yield self.db;before_commit()
        self.store=SimpleNamespace(_transaction=transaction,_observe_floor=Mock())
        self.wrap={'epoch':1,'revisionId':'a'*64,'record':'b'*64,'digest':'c'*64,'readerEpub':'owner-e','itemDigest':'d'*64}
        self.doc={'policyUntil':9000,'wraps':{'owner':self.wrap}}
        self.ids={'owner':'owner','bindings':{'owner':{'epub':'owner-e','pub':'owner-p','head':3}}}
        self.projection={'predicate':'same-group','set':'set','snapshot':{'objectSet':{'stated':1}}}
        self.current=({'policyUntil':9000},{},{'settleWindowMs':3600000})
        self.media=Mock(clock=lambda:self.now)
        self.media._latest.return_value={'owner':{'claims':{'until':9000000}}}
        self.items=SimpleNamespace(media=self.media,store=self.store,
            _authority=Mock(side_effect=lambda *a:({'projection':self.projection},self.row,self.doc,self.ids,self.current)),
            _maintenance_parent=Mock(return_value=({'epoch':1,'revisionId':'a'*64},'d'*64,'e'*64,'fence')))
        self.source=GroupOwnerWrapSource(self.items)
        patcher=patch('group_owner_wrap_source.authority_digest',return_value=b'identity');self.checkpoint=patcher.start();self.addCleanup(patcher.stop)
    def authorize(self):return self.source.authorize('tenant','owner','media','same-group','set')
    def test_owner_only_separate_permit_rechecks_after_storage_clock_tick(self):
        permit=self.authorize();self.assertEqual((permit.owner,permit.reader_epub,permit.key_commitment),('owner','owner-e','e'*64))
        self.now=101;self.assertTrue(self.source.commit(permit));self.store._observe_floor.assert_called_once_with(self.db,'owner',3)
        self.items._maintenance_parent.assert_called_with(self.db,'tenant','owner','media',self.row,self.doc,self.ids,101)
        self.media._save.assert_not_called()
    def test_scope_wrap_identity_and_expiry_refuse(self):
        for case in ['missing','scope','inactive','wrap','epoch','revision','epub','digest','record','item','expiry']:
            with self.subTest(case=case):
                self.setUp()
                if case=='missing':self.projection=None
                if case=='scope':self.projection['set']='other'
                if case=='inactive':self.current=None
                if case=='wrap':self.doc['wraps']={}
                if case=='epoch':self.wrap['epoch']=2
                if case=='revision':self.wrap['revisionId']='9'*64
                if case=='epub':self.wrap['readerEpub']='other'
                if case=='digest':self.wrap['digest']='bad'
                if case=='record':self.wrap['record']=None
                if case=='item':self.wrap['itemDigest']='bad'
                if case=='expiry':self.doc['policyUntil']=100
                with self.assertRaises(AdmissionRejected):self.authorize()
    def test_current_owner_grant_and_history_are_mandatory(self):
        self.items._maintenance_parent.side_effect=AdmissionRejected('owner grant refused')
        with self.assertRaises(AdmissionRejected):self.authorize()
        self.items._maintenance_parent.side_effect=None;self.items._authority.side_effect=AdmissionRejected('owner refused')
        with self.assertRaises(AdmissionRejected):self.authorize()
    def test_changes_after_storage_never_commit(self):
        for change in ['row','identity','wrap','expiry','permit']:
            with self.subTest(change=change):
                self.setUp();permit=self.authorize()
                if change=='row':self.row=(2,b'n'*32,b'changed')
                if change=='identity':self.checkpoint.return_value=b'changed'
                if change=='wrap':self.wrap['record']='9'*64
                if change=='expiry':self.now=102
                if change=='permit':permit=replace(permit,owner='other')
                with self.assertRaises((HistoryConflict,AdmissionRejected,KeyError)):self.source.commit(permit)
                self.store._observe_floor.assert_not_called()
        with self.assertRaises(AdmissionRejected):self.source.commit(None)
    def test_detached_owner_repair_keeps_its_scope_without_group_access(self):
        self.projection['snapshot']['objectSet']['stated']=0;self.current=None
        self.assertTrue(self.source.commit(self.authorize()))
