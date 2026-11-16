"""Signed-store policy guards with substituted native verifier and storage."""
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from signed_store_source import SignedStoreSource
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict,HistorySnapshot

class SignedStoreTests(unittest.TestCase):
    def setUp(self):
        self.now=100;self.policy={'trust':{},'activePrincipals':['owner'],'until':200};self.committed=False
        self.before_write=lambda:None
        def write(*args,**kw):
            self.before_write();kw['before_commit']();self.committed=True
        self.store=SimpleNamespace(require_authority_checkpoint=True,has_freshness=True,
            read_authority=lambda:(1,{'owner':HistorySnapshot('owner',b'{}',())}),observe_head=Mock(),
            read_ciphertext=lambda *args,**kw:(0,b''),write_verified_ciphertext=write)
        self.source=SignedStoreSource(self.store,lambda _:copy.deepcopy(self.policy),clock=lambda:self.now)
        self.head={'sequence':0,'currentKey':'owner','currentEpub':'epub'}
        self.verifier=patch('history_admission.HistoryAdmission._run_verifier',return_value=json.dumps(self.head).encode()).start()
        self.signer=patch('history_admission.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'{"current":{}}')).start()
        self.addCleanup(patch.stopall)

    def test_read_and_signed_write_use_current_native_authority(self):
        self.assertEqual(self.source.read_store_row('owner','recovery','current'),{'generation':0,'head':self.head,'row':None})
        self.assertEqual(self.source.apply_store_operation('owner','recovery',{}),1)
        self.assertTrue(self.committed)

    def test_policy_change_at_commit_prevents_write(self):
        self.before_write=lambda:self.policy.update(activePrincipals=[])
        with self.assertRaises(HistoryConflict):self.source.apply_store_operation('owner','recovery',{})
        self.assertFalse(self.committed)

    def test_clock_change_at_commit_and_inactive_owner_refuse(self):
        self.before_write=lambda:setattr(self,'now',101)
        with self.assertRaises(AdmissionRejected):self.source.apply_store_operation('owner','recovery',{})
        self.assertFalse(self.committed)
        self.policy['activePrincipals']=[]
        with self.assertRaises(AdmissionRejected):self.source.read_store_row('owner','recovery','current')

    def test_policy_change_after_read_refuses_delivery(self):
        def read(*args,**kwargs):
            self.policy['trust']={'changed':True};return 0,b''
        self.store.read_ciphertext=read
        with self.assertRaises(HistoryConflict):self.source.read_store_row('owner','recovery','current')

    def test_missing_checkpoint_and_native_refusal(self):
        self.store.has_freshness=False
        with self.assertRaises(AdmissionRejected):SignedStoreSource(self.store,lambda _:self.policy)
        self.store.has_freshness=True;self.store.require_authority_checkpoint=False
        with self.assertRaises(AdmissionRejected):SignedStoreSource(self.store,lambda _:self.policy)
        self.verifier.side_effect=AdmissionRejected('untrusted')
        with self.assertRaises(AdmissionRejected):self.source.read_store_row('owner','recovery','current')

    def test_policy_change_at_floor_boundary_is_checked_inside_operation(self):
        def observe(*args,**kwargs):
            self.policy['activePrincipals']=[]
            kwargs['before_commit']()
            self.fail('floor must not advance')
        self.store.observe_head=observe
        with self.assertRaises(HistoryConflict):self.source.read_store_row('owner','recovery','current')
