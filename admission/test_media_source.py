"""Protected journal/rollback contracts. SQLite and native work run in CI only."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from unittest import TestCase, IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

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
        self.assertTrue(self.mutate('grant',self.grant()))
        with self.assertRaises(HistoryConflict):self.mutate('grant',self.grant(grantRevision=0))

    def test_old_authenticated_fork_freezes_after_newer_cancellation(self):
        self.ready()
        self.mutate('grant',self.grant(grantRevision=2,stated=0))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(itemCiphertextDigest='9'*64))
        self.mutate('grant',self.grant(grantRevision=3))
        with self.assertRaises(AdmissionRejected):self.permit()
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
        self.assertEqual(doc['frozen'],['reader'])
        self.assertEqual(doc['conflicts'][0]['claims']['grantRevision'],1)

    def test_alternate_valid_signatures_are_not_conflicting_claims(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)['fence']
        alternate=self.grant();alternate['proof']['signature']='alternate-valid-signature'
        self.assertTrue(self.mutate('grant',alternate))
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        self.assertTrue(self.permit())
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('grant',alternate)

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

    def test_provision_requires_independent_tenant_and_rechecked_exclusivity(self):
        with self.assertRaises(AdmissionRejected):MediaSource(Mock(require_authority_checkpoint=False),TENANT)
        with self.assertRaises(AdmissionRejected):MediaSource(self.store,'00000000-0000-0000-0000-000000000000',native=self.native)
        with self.assertRaises(AdmissionRejected):MediaSource(self.store,'11234567-89ab-cdef-0123-456789abcdef',native=self.native)
        for object,until in [('foreign',200),(OBJECT,99)]:
            with self.assertRaises(AdmissionRejected):self.source.provision(object,{},until,exclusive_grant=lambda *a:True)
        with self.assertRaises(HistoryConflict):self.source.provision(OBJECT,{},200,exclusive_grant=lambda *a:True)
        calls=[]
        def once(*args):calls.append(1);return len(calls)==1
        with self.assertRaises(AdmissionRejected):self.source.provision('media_new',{},200,exclusive_grant=once)
        with self.assertRaises(AdmissionRejected):self.source.read_view('media_new',self.now)
        with self.assertRaises(AdmissionRejected):self.source.provision('media_large',{'padding':'x'*65536},200,exclusive_grant=lambda *a:True)

    def test_default_identity_loader_uses_all_accounts_from_the_held_transaction(self):
        from history_admission import HistoryAdmission
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,self.now)
            with patch.object(HistoryAdmission,'_run_verifier',return_value=encoded(self.ids)) as run:
                result=self.source._identities(db,OBJECT,doc,self.now)
        self.assertEqual(result,self.ids)
        self.assertEqual(run.call_args.kwargs['mediaObject'],OBJECT)
        self.assertEqual(run.call_args.kwargs['peers'][0]['principal'],'reader')

    def test_rejected_signature_enrollment_and_oversized_mutations_leave_state_unchanged(self):
        before=self.source.read_view(OBJECT,self.now)['fence']
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant())
        self.native[0].matches_grant.return_value=True
        for changes in [{'accessor':'foreign'},{'accessor':[]},{'owner':'foreign'},{'object':'other'}]:
            with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(**changes))
        for value in [{'claims':{},'proof':{}},{**self.grant(),'extra':1},self.grant()|{'proof':{'padding':'x'*17000}}]:
            with self.assertRaises(AdmissionRejected):self.mutate('grant',value)
        with self.assertRaises(AdmissionRejected):self.mutate('grant',{'padding':'x'*65537})
        with self.assertRaises(AdmissionRejected):self.mutate('wrap',{'padding':'x'*4097})
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)

    def test_epoch_signatures_lineage_and_observation_times_are_preserved(self):
        self.mutate('grant',self.grant())
        snapshot=self.source.read_view(OBJECT,self.now)['snapshot']
        document={'manifest':{'epoch':1,'revisionId':'b'*64,'aclSnapshot':'c'*64},'snapshot':snapshot}
        fin={'epoch':1,'revisionId':'b'*64,'previousEpoch':0,'previousFinalizationId':'','finalizationId':'d'*64}
        self.native[2].matches_manifest.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':fin})
        self.native[2].matches_manifest.return_value=True
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':{**fin,'previousEpoch':1}})
        self.native[4].verifies_history.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':fin})
        self.native[4].verifies_history.return_value=True
        self.mutate('epoch',{'document':document,'finalization':fin})
        with self.assertRaises(HistoryConflict):self.mutate('epoch',{'document':document,'finalization':fin})
        self.now=101
        next_doc={**document,'manifest':{**document['manifest'],'epoch':2,'revisionId':'9'*64}}
        next_fin={**fin,'epoch':2,'revisionId':'9'*64,'previousEpoch':1,'previousFinalizationId':'d'*64,'finalizationId':'8'*64}
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':next_doc,'finalization':{**next_fin,'previousFinalizationId':'7'*64}})
        self.mutate('epoch',{'document':next_doc,'finalization':next_fin})
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
        self.assertEqual([row['seenAt'] for row in doc['finalizations']],[100000,101000])
        self.assertEqual(doc['anchor'],'d'*64)

    def test_wrap_metadata_cannot_change_recipient_or_item_binding(self):
        self.ready()
        valid={'reader':'reader','record':'e'*64,'digest':'f'*64,'epoch':1,'revisionId':'b'*64,'readerEpub':'reader-epub','itemDigest':'a'*64}
        for field,value in [('reader',[]),('reader','foreign'),('epoch',2),('readerEpub','other'),('itemDigest','9'*64),('record','bad'),('revisionId','9'*64)]:
            with self.assertRaises(AdmissionRejected):self.mutate('wrap',{**valid,field:value})
        with self.assertRaises(AdmissionRejected):self.source.commit(None)
        with self.assertRaises(HistoryConflict):self.source.commit(replace(self.permit(),fence='0'*64))

    def test_policy_refusal_and_expiry(self):
        for until,policy in [(99,{}),(200,{'padding':'x'*60001})]:
            with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,0,policy,until,authorize=lambda *a:True)
        with self.assertRaises(HistoryConflict):self.source.replace_policy(OBJECT,99,{},200,authorize=lambda *a:True)
        with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,0,{},200,authorize=lambda *a:False)
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.source.read_view(OBJECT,self.now)

    def test_owner_view_restricts_identity_inventory_and_requires_fixed_owner(self):
        view=self.source._owner_view(TENANT,'owner',OBJECT,lambda:None)
        self.assertEqual(set(view['bindings']),{'owner'})
        self.assertEqual(view['at'],self.now)
        self.mutate('grant',self.grant())
        self.assertEqual(set(self.source._owner_view(TENANT,'owner',OBJECT,lambda:None)['bindings']),{'owner','reader'})
        with self.assertRaises(AdmissionRejected):self.source._owner_view(TENANT,'reader',OBJECT,lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._owner_view('other','owner',OBJECT,lambda:None)


class MediaAuthorityCancellationContracts(IsolatedAsyncioTestCase):
    async def test_async_entrypoints_keep_the_exact_commit_permit(self):
        source=object.__new__(MediaSource);source.slots=asyncio.Semaphore(1)
        source.authorize=Mock(return_value='permit');source.commit=Mock(return_value=True)
        self.assertEqual(await source.authorize_read(TENANT,'reader',OBJECT),'permit')
        self.assertTrue(await source.commit_delivery('permit'))
        self.assertEqual(source.commit.call_args.args[0],'permit')
        self.assertFalse(source.slots.locked())
        source._owner_view=Mock(return_value={'fence':'held'});source.mutate=Mock(return_value=True)
        self.assertEqual(await source.owner_view(TENANT,'owner',OBJECT),{'fence':'held'})
        self.assertTrue(await source.owner_mutate(TENANT,'owner',OBJECT,100,'fence','grant',{'signed':True}))
        self.assertEqual(source.mutate.call_args.args[:-1],(TENANT,'owner',OBJECT,100,'fence','grant',{'signed':True}))

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
