"""Pure units: substituted transaction and native verification boundaries."""
import copy
import json
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch
from credential_source import CredentialSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict, HistorySnapshot

T='00000000-0000-4000-8000-000000000001'
S='00000000-0000-4000-8000-000000000002'

class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.at=100
        self.policy={'trust':{},'from':0,'until':200}
        self.credential={'kind':'wallet','address':'address'}
        self.before=lambda:None
        self.committed=False
        @contextmanager
        def transaction(**kw):
            self.before()
            yield object()
            kw['before_commit']()
            self.committed=True
        self.store=SimpleNamespace(tenant=T,source=S,require_authority_checkpoint=True,
            _transaction=transaction,_observe_floor=Mock())
        self.source=CredentialSource(self.store,T,S,policy_at=lambda _:copy.deepcopy(self.policy),clock=lambda:self.at)
        self.accounts={'one':HistorySnapshot('one',b'{}',()),'two':HistorySnapshot('two',b'{}',())}
        self.lookup={'snapshot':{'completeThrough':100,'credential':self.credential,'links':[],
            'revocations':[],'history':{}},'heads':{'one':0,'two':1}}
        patch('credential_source.StatementSource._accounts',return_value=self.accounts).start()
        patch('credential_source.authority_digest',return_value=b'a'*32).start()
        self.native=patch('credential_source.HistoryAdmission._run_verifier',side_effect=lambda *a,**k:json.dumps(self.lookup)).start()
        self.addCleanup(patch.stopall)
    def read(self,**kw):return self.source.read(self.credential,100,**kw)
    def test_complete_domain_and_floors(self):
        result=self.read()
        self.assertEqual(result['tenant'],T)
        self.assertEqual(result['source'],S)
        self.assertEqual(result['authorityDigest'],'61'*32)
        self.assertTrue(self.committed)
        self.assertEqual(self.store._observe_floor.call_count,2)
        self.assertEqual(self.native.call_args.kwargs['peers'][0]['principal'],'two')
    def test_foreign_or_unprotected_store(self):
        for patching in ({'tenant':S},{'source':T},{'require_authority_checkpoint':False}):
            store=SimpleNamespace(**(vars(self.store)|patching))
            with self.assertRaises(ValueError):CredentialSource(store,T,S,policy_at=lambda _:self.policy)
        with self.assertRaises(ValueError):CredentialSource(self.store,'00000000-0000-0000-0000-000000000000',S,policy_at=lambda _:self.policy)
    def test_clock_and_cancel_and_changed_policy(self):
        for callback in (lambda:setattr(self,'at',101),lambda:self.policy.update(until=102)):
            self.at=100;self.before=callback
            with self.assertRaises(HistoryConflict):self.read()
            self.assertFalse(self.committed)
        self.before=lambda:None
        with self.assertRaises(HistoryConflict):self.read(cancel=lambda:(_ for _ in ()).throw(HistoryConflict()))
        for at in (True,-1,99):
            with self.assertRaises(HistoryConflict):self.source.read(self.credential,at)
    def test_missing_foreign_and_invalid_heads(self):
        original=copy.deepcopy(self.lookup)
        for change in ({'heads':{}},{'heads':{'one':0,'two':True}},
                {'snapshot':dict(original['snapshot'],completeThrough=99)},
                {'snapshot':dict(original['snapshot'],credential={})}):
            self.lookup=copy.deepcopy(original)|change
            with self.assertRaises(AdmissionRejected):self.read()
            self.assertFalse(self.committed)
    def test_capacity_and_failure(self):
        with self.assertRaises(AdmissionRejected):self.source.read({'x':'a'*4097},100)
        self.lookup['snapshot']['oversize']='x'*(4*1024*1024)
        with self.assertRaises(AdmissionRejected):self.read()
        self.native.side_effect=AdmissionRejected('native refused')
        with self.assertRaises(AdmissionRejected):self.read()
        self.assertFalse(self.committed)
    def test_checkpoint_failure_and_commit_cancel(self):
        self.before=lambda:(_ for _ in ()).throw(HistoryConflict('rollback'))
        with self.assertRaises(HistoryConflict):self.read()
        self.assertFalse(self.native.called)
        self.before=lambda:None
        self.store._observe_floor.side_effect=lambda *a:self.policy.update(until=101)
        with self.assertRaises(HistoryConflict):self.read()
        self.assertFalse(self.committed)

if __name__=='__main__':unittest.main()
