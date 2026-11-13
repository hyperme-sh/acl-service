"""Transaction units; the cryptographic subprocess is stubbed."""
import tempfile
import unittest
from pathlib import Path
from statement_source import StatementSource
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
TENANT = '01234567-89ab-cdef-0123-456789abcdef'

class StatementUnits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store = SqliteHistoryStore(Path(self.tmp.name) / 'history.db')
        self.store.enroll('owner', b'{}'); self.now = 100
        self.hook = lambda: None
        def verify(accounts, doc, at, rows, only):
            self.hook()
            return {'heads': {'owner': 0}, 'snapshot': {'completeThrough': at,
                'history': {'completeThrough': at, 'accounts': [], 'links': []}, 'rows': doc['rows'] + rows}}
        self.verify = verify
        self.source = StatementSource(self.store, TENANT, clock=lambda: self.now, verifier=verify)
        self.source.provision('forum', 'forum-owner', {}, 200, exclusive_grant=lambda *a: True)

    def test_append_reopen_and_stale_fence(self):
        first = self.source.read('forum', 100)
        self.assertTrue(self.source.append('forum', 100, first['fence'], [{'signed': 'one'}]))
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, first['fence'], [{}])
        reopened = StatementSource(self.store, TENANT, clock=lambda: self.now, verifier=self.verify)
        self.assertEqual(reopened.read('forum', 100)['snapshot']['rows'], [{'signed': 'one'}])

    def test_identity_change_invalidates_fence(self):
        fence = self.source.read('forum', 100)['fence']
        self.store.append('owner', 0, b'{"kind":"revoke"}')
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, fence, [{}])

    def test_policy_change_invalidates_fence(self):
        fence = self.source.read('forum', 100)['fence']
        self.source.replace_policy('forum', 0, {'new': True}, 300, authorize=lambda *a: True)
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, fence, [{}])

    def test_expiry_inside_commit_rolls_back(self):
        fence = self.source.read('forum', 100)['fence']; calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            if calls == 2: raise HistoryConflict('cancelled at commit')
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, fence, [{}], cancel)
        self.assertEqual(self.source.read('forum', 100)['snapshot']['rows'], [])
        self.hook = lambda: setattr(self, 'now', 101)
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, fence, [{}])
        self.hook = lambda: None
        self.assertEqual(self.source.read('forum', 101)['snapshot']['rows'], [])

    def test_tenant_scope_grant_and_time_boundaries(self):
        with self.assertRaises(AdmissionRejected): StatementSource(self.store, '01234567-89ab-cdef-0123-456789abcdee', verifier=self.verify)
        with self.assertRaises(AdmissionRejected): self.source.read('foreign', 100)
        with self.assertRaises(HistoryConflict): self.source.read('forum', 99)
        with self.assertRaises(AdmissionRejected): self.source.provision('second', 'forum-owner', {}, 200, exclusive_grant=lambda *a: False)
        self.now = 200
        with self.assertRaises(AdmissionRejected): self.source.read('forum', 200)

    def test_capacity_preserves_retained_rows(self):
        fence = self.source.read('forum', 100)['fence']
        for rows in [[], [{}] * 66, [{'huge': 'x' * 65536}]]:
            with self.assertRaises(AdmissionRejected): self.source.append('forum', 100, fence, rows)
        with self.assertRaises(HistoryConflict): self.source.append('forum', 100, '0' * 64, [{}])
        for i in range(16):
            fence = self.source.read('forum', 100)['fence']; self.source.append('forum', 100, fence, [{}] * 64)
        fence = self.source.read('forum', 100)['fence']
        with self.assertRaises(AdmissionRejected): self.source.append('forum', 100, fence, [{}])
        self.assertEqual(len(self.source.read('forum', 100)['snapshot']['rows']), 1024)

    def test_independent_checkpoint_rejects_graph_rollback(self):
        import hashlib
        from acl_service.infrastructure.initialize_ciphertext_freshness import initialize
        path = Path(self.tmp.name) / 'protected.db'
        store = SqliteHistoryStore(path); store.enroll('owner', b'{}')
        anchor = Path(self.tmp.name) / 'freshness.db'
        initialize(path, hashlib.sha256(path.read_bytes()).hexdigest(), anchor)
        store = SqliteHistoryStore(path, freshness_path=anchor, require_authority_checkpoint=True)
        source = StatementSource(store, TENANT, clock=lambda: self.now, verifier=self.verify)
        source.provision('forum', 'forum-owner', {}, 200, exclusive_grant=lambda *a: True)
        read = source.read('forum', 100); backup = path.read_bytes()
        source.append('forum', 100, read['fence'], [{}])
        path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected): source.read('forum', 100)

    def test_provision_rechecks_grant_and_policy_commit_rechecks_authorization(self):
        calls = 0
        def grant(*args):
            nonlocal calls
            calls += 1
            return calls == 1
        with self.assertRaises(AdmissionRejected): self.source.provision('new', 'forum-owner', {}, 200, exclusive_grant=grant)
        with self.assertRaises(AdmissionRejected): self.source.read('new', 100)
        calls = 0
        with self.assertRaises(AdmissionRejected): self.source.replace_policy('forum', 0, {}, 300, authorize=grant)
        self.now = 200
        with self.assertRaises(AdmissionRejected): self.source.read('forum', 200)

    def test_fork_and_oversized_history_rejected_before_verifier(self):
        from history_admission import FORK_PREFIX
        self.store.append('owner', 0, FORK_PREFIX + b'fork')
        with self.assertRaises(AdmissionRejected): self.source.read('forum', 100)
        other = SqliteHistoryStore(Path(self.tmp.name) / 'large.db')
        other.enroll('owner', b'x' * (4*1024*1024 + 1))
        source = StatementSource(other, TENANT, clock=lambda:100, verifier=self.verify)
        with self.assertRaises(AdmissionRejected): source.provision('large', 'forum', {}, 200, exclusive_grant=lambda *a:True)
        empty = StatementSource(SqliteHistoryStore(Path(self.tmp.name) / 'empty.db'), TENANT, clock=lambda:100, verifier=self.verify)
        with self.assertRaises(AdmissionRejected): empty.provision('empty', 'forum', {}, 200, exclusive_grant=lambda *a:True)

    def test_provision_and_policy_boundaries(self):
        grant = lambda *a:True
        for scope in ['', 'x'*129]:
            with self.assertRaises(AdmissionRejected): self.source.provision(scope, 'forum', {}, 200, exclusive_grant=grant)
        with self.assertRaises(HistoryConflict): self.source.provision('forum', 'forum', {}, 200, exclusive_grant=grant)
        with self.assertRaises(AdmissionRejected): self.source.provision('expired', 'forum', {}, 99, exclusive_grant=grant)
        with self.assertRaises(AdmissionRejected): self.source.replace_policy('forum', 0, {}, 99, authorize=grant)
        with self.assertRaises(HistoryConflict): self.source.replace_policy('forum', 9, {}, 200, authorize=grant)
        with self.assertRaises(AdmissionRejected): self.source.replace_policy('forum', 0, {'padding':'x'*(4*1024*1024)}, 200, authorize=grant)

    def test_subprocess_message_contains_only_service_selected_history_and_policy(self):
        import json
        from unittest.mock import patch
        from history_admission import HistoryAdmission
        self.source.verifier = self.source._verify
        result = {'heads':{'owner':0}, 'snapshot':{'completeThrough':100,'history':{},'rows':[]}}
        with patch.object(HistoryAdmission, '_run_verifier', return_value=json.dumps(result).encode()) as run:
            self.source.read('forum',100)
        self.assertEqual(run.call_args.args, ('owner',100))
        self.assertEqual(run.call_args.kwargs['genesis'], {})
        self.assertEqual(run.call_args.kwargs['peers'], [])
        self.assertEqual(run.call_args.kwargs['graph']['candidates'], [])
        self.assertFalse(run.call_args.kwargs['graph']['statementOnly'])

if __name__ == '__main__': unittest.main()
