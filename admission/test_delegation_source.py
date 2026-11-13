"""Signed delegation storage contract. Run only in CI."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from delegation_source import DelegationSource
from statement_source import StatementSource
from history_admission import HistoryAdmission, EnrollmentGrant, AdmissionRejected
from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize


class DelegationContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'history.db'
        f = json.loads(Path('fixture.json').read_bytes()); self.f = f; self.now = f['now']
        self.trust = {k:f[k] for k in ('jwks', 'policy', 'pinnedIss')}
        store = SqliteHistoryStore(self.path)
        history = HistoryAdmission(store, grant_for=lambda p: EnrollmentGrant(p, 'qualification', 'one-use-grant', self.now+60),
                                   trust_at=lambda _:self.trust, clock=lambda:self.now)
        history.enroll(f['genesis'], json.dumps(f['binding']).encode(), f['signature'])
        freshness = Path(self.tmp.name) / 'freshness.db'
        initialize(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest(), freshness)
        self.store = SqliteHistoryStore(self.path, freshness_path=freshness, require_authority_checkpoint=True)
        self.tenant = '01234567-89ab-cdef-0123-456789abcdef'
        self.source = DelegationSource(self.store, self.tenant, clock=lambda:self.now)
        self.rows = json.loads(subprocess.check_output(['node','delegation-fixture.mjs']))
        self.source.provision('agents', self.rows['audience'], self.trust, self.now+120, exclusive_grant=lambda *a:True)

    def read(self):
        return self.source.read('agents', self.now)

    def append(self, rows):
        return self.source.append('agents', self.now, self.read()['fence'], rows)

    def test_roundtrip_retains_cancellation_and_expired_delegation(self):
        self.assertEqual(self.read()['snapshot']['rows'], [])
        self.append(self.rows['delegations'][:1]); self.append(self.rows['revocations'][:1])
        self.now += 60
        snapshot = self.read()['snapshot']
        self.assertEqual(len(snapshot['rows']), 2)
        self.assertEqual(snapshot['completeThrough'], self.now)
        self.assertEqual(snapshot['history']['accounts'][0]['principal'], self.f['genesis'])
        with self.assertRaises(AdmissionRejected): self.append(self.rows['delegations'][1:2])

    def test_all_signatures_checked_even_duplicates_and_cancellations(self):
        self.append(self.rows['delegations'][:1])
        self.append(self.rows['delegations'][:1] * 2)
        self.assertEqual(len(self.read()['snapshot']['rows']), 1)
        for original in [self.rows['delegations'][0], self.rows['revocations'][0]]:
            row = json.loads(json.dumps(original)); row['record']['sig'] = 'bad'
            with self.assertRaises(AdmissionRejected): self.append([row])
        self.assertEqual(len(self.read()['snapshot']['rows']), 1)

    def test_unknown_cancel_wrong_audience_and_future_record_deny(self):
        with self.assertRaises(AdmissionRejected): self.append(self.rows['revocations'][:1])
        for field, value in [('audience','https://foreign.example'), ('issuedAt',self.now+1), ('principal','bad')]:
            row = json.loads(json.dumps(self.rows['delegations'][0])); row['record'][field] = value
            with self.assertRaises(AdmissionRejected): self.append([row])

    def test_scope_formats_cannot_reinterpret_statement_history(self):
        statement = StatementSource(self.store, self.tenant, clock=lambda:self.now)
        with self.assertRaises(AdmissionRejected): statement.read('agents',self.now)
        for audience in ['forum_invalid', 'https://s3r.ch/path', 'http://s3r.ch']:
            with self.assertRaises(AdmissionRejected):
                self.source.provision('bad',audience,self.trust,self.now+120,exclusive_grant=lambda *a:True)

    def test_quota_keeps_room_for_every_cancellation(self):
        self.append(self.rows['delegations'][:64])
        with self.assertRaises(AdmissionRejected): self.append(self.rows['delegations'][64:])
        self.append(self.rows['revocations'][:64])
        self.assertEqual(len(self.read()['snapshot']['rows']),128)
        fence = self.read()['fence']
        self.append(self.rows['revocations'][:64])
        self.assertEqual(self.read()['fence'],fence)

    def test_rollback_policy_change_and_missing_scope_deny(self):
        before = self.path.read_bytes(); fence = self.read()['fence']
        self.append(self.rows['delegations'][:1])
        with self.assertRaises(HistoryConflict): self.source.append('agents',self.now,fence,self.rows['delegations'][1:2])
        self.path.write_bytes(before)
        with self.assertRaises(AdmissionRejected): self.read()

    def test_provision_requires_explicit_grant_and_existing_identity(self):
        with self.assertRaises(AdmissionRejected):
            self.source.provision('other',self.rows['audience'],self.trust,self.now+120,exclusive_grant=lambda *a:False)
        with self.assertRaises(AdmissionRejected): self.source.read('other',self.now)
        self.now += 120
        with self.assertRaises(AdmissionRejected): self.read()


if __name__ == '__main__': unittest.main()
