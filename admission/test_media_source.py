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

    def catalog_fixture(self):
        owner='axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'
        prefix='media_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_'
        self.ids['owner']=owner
        self.ids['bindings'][owner]={'pub':owner,'epub':owner,'head':0}
        objects=[prefix+format(i,'032x') for i in range(6)]
        for object in objects:
            self.source.provision(object,{},10000,exclusive_grant=lambda *args:True)
        return owner,objects

    def test_owner_catalog_has_fixed_pages_without_unrelated_ids_or_positions(self):
        owner,objects=self.catalog_fixture()
        foreign='media_p_'+'0'*128+'_'+'0'*32
        self.source.provision(foreign,{},10000,exclusive_grant=lambda *args:True)
        first=self.source._owner_catalog(TENANT,owner,0,lambda:None)
        self.assertEqual(first,{'at':100,'objects':objects[:4],'nextPage':1})
        self.assertEqual(self.source._owner_catalog(TENANT,owner,1,lambda:None)['objects'],objects[4:])
        self.assertEqual(self.source._owner_catalog(TENANT,owner,15,lambda:None),{'at':100,'objects':[],'nextPage':None})
        self.assertNotIn(OBJECT,json.dumps(first))
        self.assertNotIn(foreign,json.dumps(first))
        self.ids['owner']='different-owner'
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None)['objects'],[])

    def test_owner_catalog_rejects_scope_bounds_cancellation_and_rollback(self):
        owner,objects=self.catalog_fixture()
        for tenant,writer,page in [('other',owner,0),(TENANT,'bad',0),(TENANT,owner[:-1]+'V',0),
                                  (TENANT,owner,True),(TENANT,owner,-1),(TENANT,owner,16)]:
            with self.assertRaises(AdmissionRejected):self.source._owner_catalog(tenant,writer,page,lambda:None)
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):self.source._owner_catalog(TENANT,owner,0,cancel)
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)
        self.now=100
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(objects[0],))
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)

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

    def write_metadata(self, digest='1'*64):
        return {'reader':'reader','record':digest,'digest':digest,'epoch':1,'revisionId':'b'*64,
                'readerEpub':'reader-epub','itemDigest':'a'*64}

    def cancel_view(self, **changes):
        args=dict(tenant=TENANT,writer='owner',object=OBJECT,reader='reader',cancel=lambda:None)
        args.update(changes)
        return self.source._owner_cancel_view(**args)

    def test_cancellation_draft_preserves_claims_and_current_owner_key_without_writing(self):
        self.mutate('grant',self.grant())
        before=self.source.read_view(OBJECT,self.now)['fence']
        self.ids['bindings']['owner']['pub']='rotated-owner-key'
        draft=self.cancel_view()
        self.assertEqual(draft['grant'],{**self.grant()['claims'],'stated':0,'grantRevision':2})
        self.assertEqual(draft['ownerPub'],'rotated-owner-key')
        self.assertEqual(draft['fence'],before)
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        self.mutate('grant',{'claims':draft['grant'],'proof':{'signature':'new-owner-signature'}})
        with self.assertRaises(AdmissionRejected): self.cancel_view()

    def test_cancellation_draft_refuses_wrong_scope_missing_and_frozen_grants(self):
        with self.assertRaises(AdmissionRejected):self.cancel_view()
        self.mutate('grant',self.grant())
        for args in [{'tenant':'other'},{'writer':'reader'},{'reader':'other'},{'reader':[]}]:
            with self.assertRaises(AdmissionRejected):self.cancel_view(**args)
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(until=9998000))
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def test_cancellation_draft_preserves_expired_claims_but_refuses_exhausted_revision(self):
        self.mutate('grant',self.grant(until=1))
        self.assertEqual(self.cancel_view()['grant']['until'],1)
        self.mutate('grant',self.grant(grantRevision=9007199254740991))
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def test_cancellation_draft_refuses_cancelled_work_expired_policy_and_checkpoint_tampering(self):
        self.mutate('grant',self.grant())
        with self.assertRaises(AdmissionRejected):
            self.cancel_view(cancel=lambda:(_ for _ in ()).throw(AdmissionRejected('cancelled')))
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.cancel_view()
        self.now=100
        with self.store._transaction(write=True) as db:db.execute('UPDATE media_sources SET revision=revision+1')
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def status_view(self, **changes):
        args={'tenant':TENANT,'writer':'owner','object':OBJECT,'reader':'reader','cancel':lambda:None}
        args.update(changes)
        return self.source._owner_status_view(**args)

    def test_owner_status_draft_uses_current_settled_state_without_writing(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)
        draft=self.status_view()
        self.assertEqual(draft['fence'],before['fence'])
        self.assertEqual(draft['ownerPub'],'owner-key')
        self.assertEqual(draft['status'],{'object':OBJECT,'epoch':1,'revisionId':'b'*64,
            'accessor':'reader','grantRevision':1,'stated':1,'signedAt':100000,'maxAgeMs':60000,
            'zookie':{'object':OBJECT,'objectVersion':3,'snapshotHash':'c'*64}})
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        self.mutate('grant',self.grant(grantRevision=2,until=102500))
        self.assertEqual(self.status_view()['status']['maxAgeMs'],2500)

    def test_status_draft_refuses_unbound_owner_reader_pending_and_changed_grants(self):
        self.ready()
        for args in [{'tenant':'other'},{'writer':'reader'},{'reader':'unknown'},{'reader':[]}]:
            with self.assertRaises(AdmissionRejected):self.status_view(**args)
        self.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.native[3].matches_settled.return_value=True
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.native[0].matches_grant.return_value=True
        self.mutate('grant',self.grant(grantRevision=2,epoch=2))
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.mutate('grant',self.grant(grantRevision=3,stated=0))
        with self.assertRaises(AdmissionRejected):self.status_view()

    def prepare(self, digest='1'*64, **changes):
        metadata=self.write_metadata(digest);metadata.update(changes)
        return self.source.prepare_write(TENANT,'owner',OBJECT,self.now,
            self.source.read_view(OBJECT,self.now)['fence'],metadata,digest,64)

    def test_write_reservation_survives_failure_and_commit_crosses_seconds_safely(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)['objectVersion']
        permit=self.prepare()
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
            self.assertEqual(len(doc['uploads']),1)
            self.assertEqual(doc['objectVersion'],before)
        self.now+=1
        self.assertTrue(self.source.commit_write(permit))
        current=self.source.read_view(OBJECT,self.now)['objectVersion']
        self.assertEqual(current,before+1)
        # Lost-response reconciliation preserves the already committed version.
        self.assertTrue(self.source.commit_write(self.prepare()))
        self.assertEqual(self.source.read_view(OBJECT,self.now)['objectVersion'],current)

    def test_write_commit_rejects_cancellation_identity_change_and_expiry(self):
        self.ready();permit=self.prepare()
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        with self.assertRaises(HistoryConflict):self.source.commit_write(permit)
        self.mutate('grant',self.grant(grantRevision=3));permit=self.prepare()
        self.store.append('owner',0,b'identity-change')
        with self.assertRaises(HistoryConflict):self.source.commit_write(permit)
        with self.assertRaises(AdmissionRejected):self.source.commit_write(None)
        self.now=permit.expires_at
        with self.assertRaises(AdmissionRejected):self.source.commit_write(permit)

    def test_all_reserved_bytes_count_toward_per_object_capacity(self):
        self.ready()
        for n in range(128):self.prepare(f'{n:064x}')
        before=self.source.read_view(OBJECT,self.now)['fence']
        with self.assertRaises(AdmissionRejected):self.prepare('f'*64)
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        # An identical reserved record remains reconcilable at capacity.
        self.assertTrue(self.source.commit_write(self.prepare('0'*64)))

    def test_publication_binding_and_native_owner_signature_refusals(self):
        self.ready()
        for changes in [{'record':'2'*64},{'epoch':True},{'readerEpub':'wrong'}]:
            with self.assertRaises(AdmissionRejected):self.prepare(**changes)
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.prepare()


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
        source.prepare_write=Mock(return_value='write-permit');source.commit_write=Mock(return_value=True)
        self.assertEqual(await source.prepare_wrap_write(TENANT,'owner',OBJECT,100,'fence',{},'a'*64,1),'write-permit')
        self.assertTrue(await source.commit_wrap_write('write-permit'))
        source._owner_status_view=Mock(return_value={'draft':'current'})
        self.assertEqual(await source.owner_status_view(TENANT,'owner',OBJECT,'reader'),{'draft':'current'})

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


class AllocationConsumptionContracts(MediaSourceContracts):
    def allocation(self):
        from types import SimpleNamespace
        record={'object':'media_new','owner':'owner','issuedAt':100,'sig':'signed'}
        scope=SimpleNamespace(tenant=TENANT,owner='owner',object='media_new',
            ownership_digest=hashlib.sha256(encoded(record)).hexdigest(),
            policy_digest=hashlib.sha256(encoded({})).hexdigest())
        scope.claims=lambda:{'tenant':TENANT,'owner':'owner','object':'media_new'}
        proof=SimpleNamespace(scope=scope,allocation='01234567-89ab-cdef-0123-456789abcdef',issued_at=100,expires_at=200)
        return record,proof

    def consume(self,record,proof,**kwargs):
        return self.source.consume_allocation(TENANT,'owner',record,{},10000,
            verify_grant=kwargs.pop('verify_grant',lambda at:proof),**kwargs)

    def test_atomic_allocation_retry_and_primary_rollback(self):
        record,proof=self.allocation();before=self.path.read_bytes()
        with patch.object(self.source,'_identities',return_value=self.ids):
            self.assertTrue(self.consume(record,proof))
            self.assertFalse(self.consume(record,proof))
            self.assertEqual(self.source.read_view('media_new',self.now)['snapshot'],{'entries':[]})
            self.path.write_bytes(before)
            with self.assertRaises(HistoryConflict):self.consume(record,proof)

    def test_cancellation_and_changed_grant_roll_back_all_tables(self):
        record,proof=self.allocation()
        def cancelled():raise AdmissionRejected('cancelled')
        with patch.object(self.source,'_identities',return_value=self.ids):
            with self.assertRaises(AdmissionRejected):self.consume(record,proof,cancel=cancelled)
            verifier=Mock(side_effect=[proof,proof,None])
            with self.assertRaises(AdmissionRejected):self.consume(record,proof,verify_grant=verifier)
            self.assertTrue(self.consume(record,proof))

    def test_mismatched_scope_owner_and_duplicate_object_refuse(self):
        record,proof=self.allocation()
        for name,value in [('tenant','foreign'),('owner','foreign'),('object','foreign'),('policy_digest','wrong'),('ownership_digest','wrong')]:
            old=getattr(proof.scope,name);setattr(proof.scope,name,value)
            with self.assertRaises(AdmissionRejected):self.consume(record,proof)
            setattr(proof.scope,name,old)
        with patch.object(self.source,'_identities',return_value={'owner':'foreign'}):
            with self.assertRaises(AdmissionRejected):self.consume(record,proof)
        with patch.object(self.source,'_identities',return_value=self.ids):
            self.assertTrue(self.consume(record,proof))
            proof.allocation='11234567-89ab-cdef-0123-456789abcdef'
            with self.assertRaises(HistoryConflict):self.consume(record,proof)
        for invalid in [None,{**record,'extra':True},{**record,'owner':'foreign'}]:
            with self.assertRaises(AdmissionRejected):self.consume(invalid,proof)
