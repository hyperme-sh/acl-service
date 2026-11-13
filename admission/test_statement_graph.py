"""Owner/consumer cryptographic contract; runs only in CI."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from statement_source import StatementSource
from history_admission import HistoryAdmission, EnrollmentGrant, AdmissionRejected
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

class GraphContracts(unittest.TestCase):
    def test_media_identity_view_uses_the_same_complete_enrolled_history(self):
        f=self.f
        payload={'principal':f['genesis'],'now':f['now'],
            'trust':{k:f[k] for k in ('jwks','policy','pinnedIss')},
            'genesis':f['binding'],'entries':[],'peers':[],
            'mediaObject':self.rows['forum'].replace('forum_','media_',1)}
        def resolve():
            return subprocess.run(['node','verify.mjs'],input=json.dumps(payload).encode(),stdout=subprocess.PIPE)
        result=resolve()
        self.assertEqual(result.returncode,0)
        view=json.loads(result.stdout)
        self.assertEqual(view['owner'],f['genesis'])
        self.assertEqual(set(view['bindings']),{f['genesis']})
        self.assertEqual(view['bindings'][f['genesis']]['head'],0)
        self.assertTrue(view['bindings'][f['genesis']]['epub'])
        payload['peers']=[{'principal':'foreign','genesis':{},'entries':[],'frozen':True}]
        self.assertNotEqual(resolve().returncode,0)
        payload['peers']=[]; payload['mediaObject']='media_unknown_bad'
        self.assertNotEqual(resolve().returncode,0)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / 'ledger.db'
        f = json.loads(Path('fixture.json').read_bytes()); self.f = f
        self.store = SqliteHistoryStore(path)
        trust = {k:f[k] for k in ('jwks','policy','pinnedIss')}
        history = HistoryAdmission(self.store, grant_for=lambda p: EnrollmentGrant(p,'qualification','one-use-grant',f['now']+60),
                                   trust_at=lambda _:trust, clock=lambda:f['now'])
        history.enroll(f['genesis'], json.dumps(f['binding']).encode(), f['signature'])
        freshness = Path(self.tmp.name) / 'freshness.db'
        initialize(path, hashlib.sha256(path.read_bytes()).hexdigest(), freshness)
        self.store = SqliteHistoryStore(path, freshness_path=freshness, require_authority_checkpoint=True)
        self.source = StatementSource(self.store, '01234567-89ab-cdef-0123-456789abcdef', clock=lambda:f['now'])
        self.rows = json.loads(subprocess.check_output(['node','statement-fixture.mjs']))
        self.source.provision('test', self.rows['forum'], trust, f['now']+60, exclusive_grant=lambda *a: True)
        initial = self.source.read('test', f['now'])
        self.source.append('test', f['now'], initial['fence'], [self.rows['initial']], statement_only=False)

    def test_signed_statement_roundtrip(self):
        held = self.source.read('test', self.f['now'])
        self.source.append('test', self.f['now'], held['fence'], self.rows['rows'])
        current = self.source.read('test', self.f['now'])
        self.assertEqual(len(current['snapshot']['rows']), 3)
        self.assertEqual(current['snapshot']['history']['accounts'][0]['principal'], self.f['genesis'])
        self.assertNotEqual(held['fence'], current['fence'])

    def test_forgery_wrong_soul_and_nonstatement_refused(self):
        for mutate in [lambda row: row['record'].update(sig='bad'), lambda row: row.update(soul='wrong')]:
            row = json.loads(json.dumps(self.rows['rows'][0])); mutate(row)
            with self.assertRaises(AdmissionRejected):
                self.source.append('test', self.f['now'], self.source.read('test', self.f['now'])['fence'], [row])
        with self.assertRaises(AdmissionRejected):
            self.source.append('test', self.f['now'], self.source.read('test', self.f['now'])['fence'], [self.rows['initial']])

    def test_exact_retries_are_idempotent_but_forged_duplicates_deny(self):
        at = self.f['now']
        held = self.source.read('test', at)
        self.source.append('test', at, held['fence'], self.rows['rows'] * 2)
        held = self.source.read('test', at)
        self.assertEqual(len(held['snapshot']['rows']), 3)
        self.source.append('test', at, held['fence'], self.rows['rows'])
        self.assertEqual(self.source.read('test', at)['fence'], held['fence'])
        forged = json.loads(json.dumps(self.rows['rows'][0])); forged['record']['sig'] = 'bad'
        with self.assertRaises(AdmissionRejected): self.source.append('test', at, held['fence'], [forged])

    def test_retained_writer_quota_is_enforced_inside_source_transaction(self):
        at = self.f['now']
        for rows in (self.rows['quotaRows'][:64], self.rows['quotaRows'][64:128]):
            held = self.source.read('test', at)
            self.source.append('test', at, held['fence'], rows, statement_only=False)
        held = self.source.read('test', at)
        with self.assertRaises(AdmissionRejected):
            self.source.append('test', at, held['fence'], self.rows['quotaRows'][128:])
        self.assertEqual(self.source.read('test', at)['fence'], held['fence'])
        self.source.append('test', at, held['fence'], self.rows['quotaRows'][:1])
        self.assertEqual(self.source.read('test', at)['fence'], held['fence'])

    def test_full_identity_history_still_allows_graph_reads(self):
        f = self.f
        payload = {'principal': f['genesis'], 'now': f['now'],
            'trust': {k:f[k] for k in ('jwks','policy','pinnedIss')},
            'genesis': f['binding'], 'entries': [f['wallet']] * self.rows['maxHistory'], 'peers': [],
            'graph': {'forum':self.rows['forum'], 'rows':[], 'candidates':[], 'statementOnly':False}}
        result = subprocess.run(['node','verify.mjs'], input=json.dumps(payload).encode(), stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['snapshot']['history']['completeThrough'], f['now'])
        del payload['graph']; payload['record'] = f['wallet']
        self.assertNotEqual(subprocess.run(['node','verify.mjs'], input=json.dumps(payload).encode(), stdout=subprocess.PIPE).returncode, 0)

if __name__ == '__main__': unittest.main()
