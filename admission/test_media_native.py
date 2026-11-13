"""Actual enrolled identity + Rust + checkpoint contract, CI container only."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from media_source import MediaSource
from history_admission import HistoryAdmission, EnrollmentGrant
from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize


class NativeMediaContracts(TestCase):
    def setUp(self):
        self.f=json.loads(Path('media-native-fixture.json').read_bytes()); f=self.f['identity']
        self.now=f['now'];self.owner=f['genesis'];self.object=self.f['object']
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.db';anchor=Path(self.tmp.name)/'freshness.db'
        store=SqliteHistoryStore(self.path)
        policy={k:f[k] for k in ('jwks','policy','pinnedIss')}
        admission=HistoryAdmission(store,grant_for=lambda p:EnrollmentGrant(p,'qualification','one-use-grant',f['now']+60),trust_at=lambda _:policy,clock=lambda:self.now)
        admission.enroll(self.owner,json.dumps(f['binding']).encode(),f['signature'])
        initialize(self.path,hashlib.sha256(self.path.read_bytes()).hexdigest(),anchor)
        self.store=SqliteHistoryStore(self.path,freshness_path=anchor,require_authority_checkpoint=True)
        self.tenant='01234567-89ab-cdef-0123-456789abcdef'
        self.source=MediaSource(self.store,self.tenant,clock=lambda:self.now)
        self.source.provision(self.object,policy,self.now+7200,exclusive_grant=lambda *a:True)
        self.mutate('grant',self.f['grant']);self.mutate('epoch',self.f['epoch']);self.mutate('wrap',self.f['wrap'])

    def mutate(self,operation,payload):
        return self.source.mutate(self.tenant,self.owner,self.object,self.now,
            self.source.read_view(self.object,self.now)['fence'],operation,payload)

    def ready(self):
        self.now+=3600
        self.mutate('status',self.f['status'])
        return self.source.authorize(self.tenant,self.owner,self.object)

    def test_real_pending_settlement_identity_binding_and_atomic_commit(self):
        self.assertTrue(self.source.production_ready)
        with self.assertRaises(AdmissionRejected):self.mutate('status',self.f['status'])
        permit=self.ready()
        self.assertEqual(permit.reader_epub,self.f['identity']['binding']['epub'])
        self.assertEqual(permit.revision_id,self.f['epoch']['document']['manifest']['revisionId'])
        self.assertTrue(self.source.commit(permit))

    def test_real_cancellation_revokes_before_delivery_and_rollback_refuses(self):
        permit=self.ready();backup=self.path.read_bytes()
        self.mutate('grant',self.f['cancel'])
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)

    def test_forged_native_grant_never_changes_protected_state(self):
        self.ready();before=self.source.read_view(self.object,self.now)['fence']
        forged=json.loads(json.dumps(self.f['cancel']));forged['proof']['signature']='0'*128
        with self.assertRaises(AdmissionRejected):self.mutate('grant',forged)
        self.assertEqual(self.source.read_view(self.object,self.now)['fence'],before)
