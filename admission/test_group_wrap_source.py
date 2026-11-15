"""Mock-only group wrap reservation and final-delivery unit contracts."""
import copy
from dataclasses import replace
from unittest import TestCase
from group_wrap_source import GroupWrapSource
import test_group_key_source as fixture
from unittest.mock import patch
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict


class GroupWrapSourceTests(TestCase):
    def setUp(self):
        self.fx=fixture.GroupKeySourceTests('test_current_snapshot_and_scope_bound_view')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.fx.ready_read()
        patcher=patch("group_wrap_source.authority_digest",side_effect=lambda db:self.fx.digest(db))
        patcher.start();self.addCleanup(patcher.stop)
        def save(db,predicate,set_id,held,document):
            self.fx.document=copy.deepcopy(document)
            self.fx.retain(held.revision+1)
        self.fx.journal.write.side_effect=save
        self.source=GroupWrapSource(self.fx.source)
        self.metadata={'reader':'member','readerEpub':'member-epub','epoch':1,'revisionId':'a'*64,'digest':'d'*64}

    def prepare(self,metadata=None,length=33,**changes):
        view=self.fx.source.view(*self.fx.args)
        values=dict(tenant='tenant',owner='owner',predicate='same-group',set_id='set_a',at=100,
                    fence=view['fence'],metadata=self.metadata if metadata is None else metadata,length=length)
        values.update(changes)
        return self.source.prepare(**values)

    def test_reservation_precedes_publication_and_exact_retry(self):
        permit=self.prepare()
        self.assertEqual(self.fx.document['wraps'],[])
        self.assertEqual(self.fx.document['uploads']['d'*64]['length'],33)
        with self.assertRaises(AdmissionRejected):self.source.authorize_read('tenant','member','same-group','set_a')
        self.assertTrue(self.source.commit(permit))
        read=self.source.authorize_read('tenant','member','same-group','set_a')
        self.assertEqual((read.digest,read.length,read.key.reader),('d'*64,33,'member'))
        self.assertTrue(self.source.commit_read(read))
        retry=self.prepare()
        self.assertTrue(self.source.commit(retry))
        self.assertEqual(len(self.fx.document['wraps']),1)
        self.assertEqual(len(self.fx.document['uploads']),1)

    def test_wrong_scope_length_fence_and_metadata_refuse(self):
        for length in [True,0,65537]:
            with self.assertRaises(AdmissionRejected):self.prepare(length=length)
        with self.assertRaises(AdmissionRejected):self.prepare(owner='member')
        with self.assertRaises(HistoryConflict):self.prepare(fence='wrong')
        for metadata in [{},[],{**self.metadata,'extra':1},
                         *[{**self.metadata,k:v} for k,v in [('reader','owner'),('readerEpub','other'),('epoch',True),
                             ('epoch',0),('revisionId','f'*64),('digest','bad')]]]:
            with self.assertRaises(AdmissionRejected):self.prepare(metadata)
        self.fx.source.native.verifies_history.return_value=False
        with self.assertRaises(AdmissionRejected):self.prepare()
        self.fx.source.native.verifies_history.return_value=True
        self.fx.document.pop('allocation');self.fx.retain()
        with self.assertRaises(AdmissionRejected):self.prepare()

    def test_reservations_are_immutable_and_bounded(self):
        self.prepare()
        with self.assertRaises(HistoryConflict):self.prepare(length=34)
        with self.assertRaises(HistoryConflict):self.prepare({**self.metadata,'digest':'e'*64})
        self.fx.document['uploads']={str(i):{} for i in range(4096)};self.fx.retain()
        with self.assertRaises(AdmissionRejected):self.prepare()
        self.fx.document['uploads']={};self.fx.retain()
        self.fx.media._group_withdrawal_capacity.return_value=9007199254740991
        with self.assertRaises(AdmissionRejected):self.prepare()

    def test_commit_revalidates_permit_and_current_authority(self):
        permit=self.prepare()
        for value in [None,replace(permit,expires_at=True),replace(permit,expires_at=100),
                      replace(permit,expires_at=104),replace(permit,fence=None)]:
            with self.assertRaises(AdmissionRejected):self.source.commit(value)
        with self.assertRaises(HistoryConflict):self.source.commit(replace(permit,fence='wrong'))
        self.fx.digest.return_value=b'changed'
        with self.assertRaises(HistoryConflict):self.source.commit(permit)
        self.fx.digest.return_value=b'authority'
        self.fx.origin._cohort.return_value['cohort']['members'][0]['stated']=0
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.assertEqual(self.fx.document['wraps'],[])

    def test_delivery_refuses_changed_wrap_and_retained_history(self):
        permit=self.prepare();self.source.commit(permit)
        read=self.source.authorize_read('tenant','member','same-group','set_a')
        for changed in [None,replace(read,key=None)]:
            with self.assertRaises(AdmissionRejected):self.source.commit_read(changed)
        with self.assertRaises(HistoryConflict):self.source.commit_read(replace(read,digest='f'*64))
        self.fx.retain(99)
        with self.assertRaises(HistoryConflict):self.source.commit_read(read)
        self.fx.document['uploads']={};self.fx.retain(100)
        with self.assertRaises(AdmissionRejected):self.source.authorize_read('tenant','member','same-group','set_a')

    def test_invalid_reserved_length_or_missing_reservation_refuses_commit(self):
        permit=self.prepare()
        # Construct a fresh source-bound permit against a corrupted reservation;
        # this exercises the retained-state guard separately from the HMAC fence.
        for uploads in [{},{permit.digest:{'metadata':self.metadata,'length':34}}]:
            self.fx.document['uploads']=uploads;self.fx.retain()
            fence=self.source._fence(self.fx.db,self.fx.held,permit)
            with self.assertRaises(AdmissionRejected):self.source.commit(replace(permit,fence=fence))
