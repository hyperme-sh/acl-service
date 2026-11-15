"""Creation authorization contracts; persistent journal contracts run in CI."""
from contextlib import contextmanager
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from group_source import GroupSource
from media_source import MediaSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


class GroupCreationContracts(TestCase):
    def setUp(self):
        self.source = object.__new__(GroupSource)
        self.db = object()
        self.media = Mock(tenant='tenant')
        self.media._load.return_value = (('held',), {'policy': {'trusted': True}, 'policyUntil': 1000})
        self.media.identities.return_value = {'owner': 'owner'}
        self.media._fence.return_value = 'fence'
        self.media._group_key = MediaSource._group_key
        self.media._group_policy_shape = MediaSource._group_policy_shape
        self.source.media = self.media
        self.source.store = Mock()
        @contextmanager
        def transaction(*, write, before_commit):
            yield self.db
            before_commit()
        self.source.store._transaction.side_effect = transaction
        self.source.journal = Mock()
        self.source.journal.read.return_value = None
        self.cohort = {'cohort': {'setOwner': 'owner', 'members': []}, 'bindings': {'owner': {'pub': 'current-key', 'epub': 'current-epub'}}}
        self.projection = patch.object(self.source, '_cohort', return_value=self.cohort).start()
        self.addCleanup(patch.stopall)
        self.verifier = patch('group_source.GroupEpochConfigVerifier').start().return_value
        self.verifier.matches_config.return_value = True
        self.config = dict(owner='owner', setId='set_a', predicate='same-group', settleWindowMs=3600000, configRevision=0, signature='signed')
        self.args = ('tenant', 'owner', 'anchor', 100, 'same-group', 'set_a')

    def test_creation_uses_current_key_and_copies_trusted_policy_without_membership(self):
        view = self.source.creation_view(*self.args)
        self.assertEqual(view['context']['ownerPub'], 'current-key')
        self.assertTrue(self.source.create(*self.args, view['fence'], self.config))
        proof, expected = map(json.loads, self.verifier.matches_config.call_args.args)
        self.assertEqual(proof, self.config)
        self.assertEqual(expected, {**view['context'], 'settleWindowMs': 3600000, 'configRevision': 0})
        saved = self.source.journal.write.call_args.args
        self.assertEqual(saved[:4], (self.db, 'same-group', 'set_a', None))
        self.assertEqual(saved[4], {'policy': {'trusted': True}, 'policyUntil': 1000, 'configs': [self.config], 'rows': [], 'epochs': [], 'wraps': []})
        self.projection.assert_called_with(self.db, {'trusted': True}, 100, 'same-group', 'set_a', [])
        self.assertGreaterEqual(self.media._guard.call_count, 4)

    def test_wrong_tenant_anchor_owner_or_set_owner_refuses(self):
        for args in [('other', *self.args[1:]), ('tenant', 'other', *self.args[2:])]:
            with self.assertRaises(AdmissionRejected): self.source.creation_view(*args)
        self.cohort['cohort']['setOwner'] = 'other'
        with self.assertRaises(AdmissionRejected): self.source.creation_view(*self.args)
        self.source.journal.write.assert_not_called()

    def test_existing_group_and_changed_authority_refuse(self):
        view = self.source.creation_view(*self.args)
        self.source.journal.read.return_value = object()
        with self.assertRaises(HistoryConflict): self.source.create(*self.args, view['fence'], self.config)
        self.source.journal.read.return_value = None
        self.media._fence.return_value = 'new-authority'
        with self.assertRaises(HistoryConflict): self.source.create(*self.args, view['fence'], self.config)
        self.source.journal.write.assert_not_called()

    def test_scope_bound_fence_signature_and_shape_refuse(self):
        view = self.source.creation_view(*self.args)
        other = (*self.args[:-1], 'set_b')
        with self.assertRaises(HistoryConflict): self.source.create(*other, view['fence'], self.config)
        with self.assertRaises(HistoryConflict): self.source.create(*self.args, None, self.config)
        self.verifier.matches_config.return_value = False
        with self.assertRaises(AdmissionRejected): self.source.create(*self.args, view['fence'], self.config)
        with self.assertRaises(AdmissionRejected): self.source.create(*self.args, view['fence'], {})
        self.source.journal.write.assert_not_called()

    def test_cohort_native_call_carries_only_current_accounts_and_scope(self):
        account = SimpleNamespace(genesis=b'{}', entries=())
        self.media._accounts.return_value = {'owner': account}
        with patch('group_source.HistoryAdmission') as runner, patch('group_source._peer_inputs', return_value=['peers']):
            runner.return_value._run_verifier.return_value = json.dumps(self.cohort)
            result = GroupSource._cohort(self.source, self.db, {'trusted': True}, 100, 'same-group', 'set_a', [])
            self.assertEqual(result, self.cohort)
            self.assertEqual(runner.return_value._run_verifier.call_args.kwargs['groupCohortGraph'], {'predicate':'same-group','set':'set_a','rows':[]})
            self.assertEqual(runner.call_args.kwargs['trust_at']('ignored'), {'trusted': True})
            self.assertIsNone(runner.call_args.kwargs['grant_for']('ignored'))

    def test_creation_reconciliation_is_exact_and_independent_of_anchor_after_commit(self):
        absent = self.source.creation_state(*self.args, self.config)
        self.assertEqual(absent['state'], 'absent')
        saved = {'policy': {'trusted': True}, 'policyUntil': 1000, 'rows': [], 'configs': [self.config]}
        self.source.journal.read.return_value = SimpleNamespace(document=json.dumps(saved))
        self.media._load.side_effect = AdmissionRejected('anchor deleted')
        self.assertEqual(self.source.creation_state(*self.args, self.config), {'at': 100, 'state': 'applied'})
        self.source.journal.write.assert_not_called()
        with self.assertRaises(HistoryConflict):
            self.source.creation_state(*self.args, {**self.config, 'signature': 'different'})
        with self.assertRaises(AdmissionRejected):
            self.source.creation_state('wrong', *self.args[1:], self.config)
        with self.assertRaises(AdmissionRejected):
            self.source.creation_state('tenant', 'wrong', *self.args[2:], self.config)
        saved['policyUntil'] = 100
        self.source.journal.read.return_value = SimpleNamespace(document=json.dumps(saved))
        with self.assertRaises(AdmissionRejected): self.source.creation_state(*self.args, self.config)
