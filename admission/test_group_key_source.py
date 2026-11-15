"""Mock-only protected group key history unit tests."""
from contextlib import contextmanager
import copy
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from group_key_source import GroupKeySource, MAX_SAFE
from media_source import MediaSource
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


class GroupKeySourceTests(TestCase):
    def setUp(self):
        self.db = object()
        self.media = Mock(tenant='tenant')
        self.media._group_key = MediaSource._group_key
        self.media._group_withdrawal_capacity.return_value = 0
        self.store, self.journal = Mock(), Mock()
        @contextmanager
        def transaction(*, write, before_commit):
            yield self.db
            before_commit()
        self.store._transaction.side_effect = transaction
        self.origin = Mock(media=self.media, store=self.store, journal=self.journal)
        self.origin._cohort.return_value = {'cohort': {'setOwner': 'owner', 'members': [
            {'accessor': 'member', 'stated': 1, 'hamState': 2}]}, 'bindings': {
                'owner': {'pub': 'owner-key', 'epub': 'owner-epub', 'head': 3},
                'member': {'pub': 'member-key', 'epub': 'member-epub', 'head': 4}}}
        with patch('group_key_source.GroupEpochVerifier'), patch('group_key_source.GroupEpochConfigVerifier'):
            self.source = GroupKeySource(self.origin)
        self.source.native.matches_manifest.return_value = True
        self.source.native.verifies_history.return_value = True
        self.source.configs.matches_config.return_value = True
        self.digest = patch('group_key_source.authority_digest', return_value=b'authority').start()
        self.addCleanup(patch.stopall)
        self.config = dict(owner='owner',setId='set_a',predicate='same-group',settleWindowMs=3600000,configRevision=0,signature='sig')
        self.document = {'policy': {}, 'policyUntil': 1000, 'configs': [self.config], 'rows': [], 'epochs': [], 'wraps': []}
        self.retain()
        self.args = ('tenant', 'owner', 100, 'same-group', 'set_a')
        self.view = self.source.view(*self.args)
        self.command = {'document': {'snapshot': self.view['snapshot'], 'manifest': {
            'object': 'set_a', 'previousEpoch': 0, 'epoch': 1, 'revisionId': 'a'*64,
            'settleWindowMs': 3600000}}, 'finalization': {
            'object': 'set_a', 'previousEpoch': 0, 'epoch': 1, 'revisionId': 'a'*64,
            'candidateRevisionIds': ['a'*64], 'previousFinalizationId': '', 'finalizationId': 'b'*64}}

    def retain(self, revision=1):
        self.held = SimpleNamespace(document=encoded(self.document), nonce=b'n'*32, revision=revision)
        self.journal.read.return_value = self.held

    def append(self, command=None, fence=None):
        return self.source.append(*self.args, self.view['fence'] if fence is None else fence,
                                  self.command if command is None else command)

    def commit(self):
        self.append()
        self.document = self.journal.write.call_args.args[-1]
        self.retain(2)
        self.journal.write.reset_mock()
        self.view = self.source.view(*self.args)

    def test_current_snapshot_and_scope_bound_view(self):
        snapshot = self.view['snapshot']
        self.assertEqual(snapshot['ownerIdentityHead'], 3)
        self.assertEqual(snapshot['ownerEncryptionPub'], 'owner-epub')
        self.assertEqual(snapshot['members'], [{'accessor':'member','stated':1,'hamState':2,
            'signingPub':'member-key','encryptionPub':'member-epub','identityHead':4}])
        self.assertEqual((self.view['previousEpoch'],self.view['previousFinalizationId']), (0,''))
        self.journal.write.assert_not_called()
        self.origin._cohort.assert_called_with(self.db, {}, 100, 'same-group', 'set_a', [])
        self.assertNotEqual(self.view['fence'], self.source.view(*self.args[:-1], 'set_b')['fence'])

    def test_append_records_server_time_and_exact_native_history(self):
        self.assertTrue(self.append())
        saved = self.journal.write.call_args.args[-1]
        row = saved['epochs'][0]
        self.assertEqual(row['expected'], {'object':'set_a','ownerPub':'owner-key','epoch':1,'revisionId':'a'*64})
        self.assertEqual(row['finalization']['seenAt'], 100000)
        history = json.loads(self.source.native.verifies_history.call_args.args[0])
        self.assertEqual(history['minimumEpoch'], 1)
        self.assertEqual(history['anchorFinalizationId'], 'b'*64)
        self.assertEqual(history['current'], self.view['snapshot'])
        self.assertEqual(history['config'], self.config)
        self.assertGreaterEqual(self.media._guard.call_count, 4)

    def test_recovery_is_exact_and_retry_does_not_restart_settlement(self):
        self.assertEqual(self.source.state(*self.args, self.command)['state'], 'absent')
        self.commit()
        self.assertEqual(self.source.state(*self.args, self.command)['state'], 'applied')
        self.assertTrue(self.append())
        self.journal.write.assert_not_called()
        self.assertEqual(self.document['epochs'][0]['finalization']['seenAt'], 100000)
        changed = copy.deepcopy(self.command)
        changed['finalization']['signature'] = 'different'
        self.assertEqual(self.source.state(*self.args, changed)['state'], 'absent')
        with self.assertRaises(AdmissionRejected): self.append(changed)
        self.assertEqual(self.view['previousEpoch'], 1)
        self.assertEqual(self.view['previousFinalizationId'], 'b'*64)

    def test_scope_expiry_missing_group_and_policy_refuse(self):
        for args in [('other',*self.args[1:]),('tenant','other',*self.args[2:])]:
            with self.assertRaises(AdmissionRejected): self.source.view(*args)
        self.journal.read.return_value = None
        with self.assertRaises(AdmissionRejected): self.source.view(*self.args)
        self.document['policyUntil'] = 100
        self.retain()
        with self.assertRaises(AdmissionRejected): self.source.view(*self.args)
        self.document['policyUntil'] = 1000
        self.retain()
        self.source.configs.matches_config.return_value = False
        with self.assertRaises(AdmissionRejected): self.source.view(*self.args)
        self.journal.write.assert_not_called()

    def test_fence_changes_with_authority_or_document_and_bad_commands_refuse(self):
        self.digest.return_value = b'rotated'
        with self.assertRaises(HistoryConflict): self.append()
        self.digest.return_value = b'authority'
        for fence in [1,'wrong']:
            with self.assertRaises(HistoryConflict): self.append(fence=fence)
        for command in [None, {}, [], {'document':{},'finalization':{}},
                        {'document':{'manifest':[],'snapshot':{}},'finalization':{}},
                        {'document':{},'finalization':'x'*65536}]:
            with self.assertRaises(AdmissionRejected): self.source.state(*self.args, command)
        self.journal.write.assert_not_called()

    def test_current_successor_signature_and_history_required(self):
        for field,value in [('epoch',2),('previousEpoch',1),('settleWindowMs',1)]:
            command = copy.deepcopy(self.command)
            command['document']['manifest'][field] = value
            with self.assertRaises(AdmissionRejected): self.append(command)
        for field,value in [('previousEpoch',1),('epoch',2),('previousFinalizationId','x'),
                            ('revisionId','c'*64),('candidateRevisionIds',['a'*64,'c'*64])]:
            command=copy.deepcopy(self.command); command['finalization'][field]=value
            with self.assertRaises(AdmissionRejected): self.append(command)
        command=copy.deepcopy(self.command);command['document']['snapshot']['ownerIdentityHead']=2
        with self.assertRaises(AdmissionRejected): self.append(command)
        self.source.native.matches_manifest.return_value=False
        with self.assertRaises(AdmissionRejected): self.append()
        self.source.native.matches_manifest.return_value=True
        self.source.native.verifies_history.return_value=False
        with self.assertRaises(AdmissionRejected): self.append()
        self.journal.write.assert_not_called()

    def test_capacity_preserves_withdrawals(self):
        self.media._group_withdrawal_capacity.return_value=MAX_SAFE
        with self.assertRaises(AdmissionRejected): self.append()
        self.media._group_withdrawal_capacity.return_value=0
        self.document['wraps']=['x'*(4*1024*1024)]
        self.retain();self.view=self.source.view(*self.args)
        with self.assertRaises(AdmissionRejected): self.append()
        self.document['wraps']=[]
        self.document['epochs']=[{'document':{},'finalization':{'proof':{'epoch':1,'finalizationId':'b'*64}}}]*64
        self.retain()
        with self.assertRaises(AdmissionRejected): self.source.view(*self.args)
        with self.assertRaises(AdmissionRejected): self.source.append(*self.args,self.source._fence(self.db,self.held,100,'same-group','set_a'),self.command)
        self.document['epochs']=[{'document':{},'finalization':{'proof':{'epoch':MAX_SAFE,'finalizationId':'b'*64}}}]
        self.retain()
        with self.assertRaises(AdmissionRejected): self.source.view(*self.args)
        self.journal.write.assert_not_called()
