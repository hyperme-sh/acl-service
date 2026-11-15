"""Transfer source unit contracts with a substituted native boundary."""
import copy
import json
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch
from device_transfer_source import DeviceTransferSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict, HistorySnapshot


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.at = 100
        self.scope = {'tenant':'tenant','application':'app','audience':'test','sourceOrigin':'https://a.example','destinationOrigin':'https://b.example'}
        self.identity = {'principal':'owner','pub':'pub','epub':'epub','rotationSeq':1}
        self.policy = {'until':200,'activePrincipals':['owner'],'scopes':[self.scope],'trust':{}}
        self.guard = lambda: None
        @contextmanager
        def transaction(**kwargs):
            self.guard()
            yield object()
            kwargs['before_commit']()
        store = SimpleNamespace(tenant='tenant',source='source',require_authority_checkpoint=True,_transaction=transaction)
        self.source = DeviceTransferSource(store, lambda _:copy.deepcopy(self.policy), clock=lambda:self.at)
        self.source._accounts = Mock(return_value={'owner':HistorySnapshot('owner',b'{}',())})
        self.digest = patch('device_transfer_source.authority_digest',return_value=b'a'*32).start()
        self.verify = patch('device_transfer_source.HistoryAdmission._run_verifier',return_value=json.dumps({'identity':self.identity,'history':{}}).encode()).start()
        self.addCleanup(patch.stopall)
        self.binding = {'scope':self.scope,'identity':self.identity,'session':'s','transcript':'t','expiresAt':120000}

    def read(self, **kw): return self.source.read('owner', self.scope, self.identity, self.binding, **kw)

    def test_fresh_checkpoint_binds_scope_and_full_transcript(self):
        first=self.read()
        self.assertEqual(first['checkpoint']['validUntil'],105000)
        self.assertEqual(self.read(expected_revision=first['checkpoint']['revision']),first)
        self.binding['transcript']='another'
        with self.assertRaises(HistoryConflict):self.read(expected_revision=first['checkpoint']['revision'])

    def test_rotation_or_checkpoint_change_refuses(self):
        first=self.read()['checkpoint']['revision']
        self.digest.return_value=b'b'*32
        with self.assertRaises(HistoryConflict):self.read(expected_revision=first)
        self.verify.return_value=json.dumps({'identity':{**self.identity,'pub':'rotated'},'history':{}}).encode()
        with self.assertRaises(AdmissionRejected):self.read()

    def test_retired_scope_missing_and_expired_policy_refuse(self):
        self.policy['activePrincipals']=[]
        with self.assertRaises(AdmissionRejected):self.read()
        self.policy['activePrincipals']=['owner'];self.policy['scopes']=[]
        with self.assertRaises(AdmissionRejected):self.read()
        self.policy['scopes']=[self.scope];self.binding['expiresAt']=100000
        with self.assertRaises(AdmissionRejected):self.read()
        self.source._accounts.return_value={}
        with self.assertRaises(AdmissionRejected):self.read()

    def test_clock_cancel_policy_and_store_fail_closed(self):
        self.guard=lambda:setattr(self,'at',101)
        with self.assertRaises(HistoryConflict):self.read()
        self.guard=lambda:self.policy.update(activePrincipals=[])
        with self.assertRaises(HistoryConflict):self.read()
        self.guard=lambda:None;self.policy['activePrincipals']=['owner']
        with self.assertRaises(HistoryConflict):self.read(cancel=lambda:(_ for _ in ()).throw(HistoryConflict()))
        self.verify.side_effect=AdmissionRejected('unavailable')
        with self.assertRaises(AdmissionRejected):self.read()
