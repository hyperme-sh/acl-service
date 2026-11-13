"""Protected journal/rollback contracts. SQLite and native work run in CI only."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from unittest import TestCase, IsolatedAsyncioTestCase
from unittest.mock import Mock

from media_source import MediaSource, encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

TENANT='01234567-89ab-cdef-0123-456789abcdef'
OBJECT='media_test'


class MediaSourceContracts(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.db'; self.anchor=Path(self.tmp.name)/'freshness.db'
        store=SqliteHistoryStore(self.path)
        for who in ('owner','reader'): store.enroll(who,b'{}')
        initialize(self.path,hashlib.sha256(self.path.read_bytes()).hexdigest(),self.anchor)
        self.store=SqliteHistoryStore(self.path,freshness_path=self.anchor,require_authority_checkpoint=True)
        self.now=100
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner-key','epub':'owner-epub','head':0},
                                             'reader':{'pub':'reader-key','epub':'reader-epub','head':0}}}
        self.identities=Mock(side_effect=lambda *args:json.loads(json.dumps(self.ids)))
        self.native=tuple(Mock() for _ in range(5))
        self.native[0].matches_grant.return_value=True
        self.native[1].matches_status.return_value=True
        self.native[2].matches_manifest.return_value=True
        self.native[3].matches_settled.return_value=True
        self.native[4].verifies_history.return_value=True
        self.source=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        self.source.provision(OBJECT,{},10000,exclusive_grant=lambda *args:True)

    def mutate(self,operation,payload,**kwargs):
        fence=self.source.read_view(OBJECT,self.now)['fence']
        return self.source.mutate(TENANT,'owner',OBJECT,self.now,fence,operation,payload,**kwargs)

    def grant(self,**changes):
        claims={'object':OBJECT,'owner':'owner','accessor':'reader','from':0,'until':9999000,
                'stated':1,'epoch':1,'grantRevision':1,'itemCiphertextDigest':'a'*64,**changes}
        return {'claims':claims,'proof':{'grantBytes':'signed','signature':'owner-signature'}}

    def ready(self):
        self.mutate('grant',self.grant())
        snapshot=self.source.read_view(OBJECT,self.now)['snapshot']
        self.mutate('epoch',{'document':{'manifest':{'epoch':1,'revisionId':'b'*64,'aclSnapshot':'c'*64},'snapshot':snapshot},
            'finalization':{'epoch':1,'revisionId':'b'*64,'previousEpoch':0,'previousFinalizationId':'','finalizationId':'d'*64}})
        self.mutate('wrap',{'reader':'reader','record':'e'*64,'digest':'f'*64,'epoch':1,'revisionId':'b'*64,
                            'readerEpub':'reader-epub','itemDigest':'a'*64})
        self.mutate('status',{'accessor':'reader','signedAt':100000,'maxAgeMs':60000})

    def permit(self): return self.source.authorize(TENANT,'reader',OBJECT)

    def test_private_view_and_delivery_commit_share_protected_history(self):
        self.ready(); permit=self.permit()
        self.assertEqual((permit.reader_epub,permit.epoch,permit.revision_id),('reader-epub',1,'b'*64))
        self.assertTrue(self.source.commit(permit))
        with self.assertRaises(HistoryConflict): self.source.commit(permit)
        with self.store._transaction(write=False) as db:
            self.assertEqual(self.source._load(db,OBJECT,self.now)[1]['floor'],1)
        self.assertFalse(self.source.production_ready)
        self.assertFalse(hasattr(self.source,'append'))

    def test_identity_acl_policy_and_wrap_changes_invalidate_delivery(self):
        self.ready(); permit=self.permit()
        self.store.append('reader',0,b'{"kind":"revoke"}')
        with self.assertRaises(HistoryConflict):self.source.commit(permit)
        permit=self.permit(); self.ids['bindings']['reader']['epub']='rotated'
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.ids['bindings']['reader']['epub']='reader-epub'
        permit=self.permit(); self.mutate('grant',self.grant(grantRevision=2,stated=0))
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)

    def test_status_and_pending_epoch_fail_closed(self):
        self.ready()
        self.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()
        self.native[3].matches_settled.return_value=True
        self.native[1].matches_status.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()
        self.native[1].matches_status.return_value=True
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()

    def test_restore_of_old_database_is_rejected_by_independent_checkpoint(self):
        self.ready(); backup=self.path.read_bytes()
        self.mutate('grant',self.grant(grantRevision=2,stated=0))
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):self.permit()
        restarted=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        with self.assertRaises(AdmissionRejected):restarted.authorize(TENANT,'reader',OBJECT)

    def test_signed_forks_freeze_even_after_cancellation_and_restart(self):
        self.ready()
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(itemCiphertextDigest='9'*64))
        with self.assertRaises(AdmissionRejected):self.permit()
        restarted=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        with self.assertRaises(AdmissionRejected):restarted.authorize(TENANT,'reader',OBJECT)

    def test_exact_retry_keeps_fence_and_stale_revision_is_refused(self):
        self.mutate('grant',self.grant())
        prior=self.source.read_view(OBJECT,self.now)['fence']
        self.mutate('grant',self.grant())
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],prior)
        self.mutate('grant',self.grant(grantRevision=2))
        with self.assertRaises(HistoryConflict):self.mutate('grant',self.grant())

    def test_cancellation_capacity_is_reserved_when_live_grants_are_full(self):
        for revision in range(1,65): self.mutate('grant',self.grant(grantRevision=revision))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(grantRevision=65))
        self.mutate('grant',self.grant(grantRevision=65,stated=0))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(grantRevision=66,stated=0))

    def test_policy_update_and_cancellation_guard_are_rechecked_at_commit(self):
        self.ready(); permit=self.permit()
        with self.store._transaction(write=False) as db: revision=self.source._load(db,OBJECT,self.now)[0][0]
        calls=[]
        def auth(*args): calls.append(1); return len(calls)==1
        with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,revision,{'new':True},500,authorize=auth)
        self.assertTrue(self.source.commit(permit))
        with self.store._transaction(write=False) as db: revision=self.source._load(db,OBJECT,self.now)[0][0]
        permit=self.permit()
        self.source.replace_policy(OBJECT,revision,{'new':True},500,authorize=lambda *args:True)
        with self.assertRaises(HistoryConflict):self.source.commit(permit)
        calls=[]
        def cancel():
            calls.append(1)
            if len(calls)>1:raise HistoryConflict('cancelled')
        with self.assertRaises(HistoryConflict):self.mutate('grant',self.grant(grantRevision=2,stated=0),cancel=cancel)
        self.assertTrue(self.permit())

    def test_cross_tenant_subject_timing_and_malformed_mutations_refuse(self):
        self.ready()
        for tenant,reader,object in [('other','reader',OBJECT),(TENANT,'foreign',OBJECT),(TENANT,'reader','media_missing')]:
            with self.assertRaises(AdmissionRejected):self.source.authorize(tenant,reader,object)
        with self.assertRaises(HistoryConflict):
            self.source.mutate(TENANT,'reader',OBJECT,self.now,self.source.read_view(OBJECT,self.now)['fence'],'grant',self.grant())
        for op,payload in [('bad',{}),('grant',{}),('epoch',{}),('wrap',{}),('status',{})]:
            with self.assertRaises(AdmissionRejected):self.mutate(op,payload)
        permit=self.permit(); self.now=permit.expires_at
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        with self.assertRaises(AdmissionRejected):self.source.commit(replace(permit,fence='0'*64))


class MediaAuthorityCancellationContracts(IsolatedAsyncioTestCase):
    async def test_cancelled_worker_keeps_slot_and_refuses_late_commit(self):
        source=object.__new__(MediaSource); source.slots=asyncio.Semaphore(1)
        entered=threading.Event(); release=threading.Event(); committed=[]
        def work(guard):
            entered.set(); release.wait(5); guard(); committed.append(True)
        task=asyncio.create_task(source._work(work))
        try:
            for _ in range(100):
                if entered.is_set():break
                await asyncio.sleep(.01)
            self.assertTrue(entered.is_set())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
            with self.assertRaises(HistoryConflict):await source._work(work)
        finally:release.set()
        for _ in range(100):
            if not source.slots.locked():break
            await asyncio.sleep(.01)
        self.assertFalse(source.slots.locked()); self.assertFalse(committed)
