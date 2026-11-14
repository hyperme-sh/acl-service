"""Actual enrolled identity + Rust + checkpoint contract, CI container only."""
import hashlib
import asyncio
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from media_source import MediaSource
from history_admission import HistoryAdmission, EnrollmentGrant
from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize
from acl_service.infrastructure.media_bindings import MediaSettings, _provisioned, _source
from uuid import UUID


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
        if operation == 'epoch':
            self.assertEqual(self.source.read_view(self.object,self.now)['snapshot']['entries'][0]['hamState'],0)
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
        draft=self.source._owner_cancel_view(self.tenant,self.owner,self.object,self.owner,lambda:None)
        self.assertEqual(draft['grant'],self.f['cancel']['claims'])
        self.assertEqual(draft['ownerPub'],self.owner)
        self.mutate('grant',self.f['cancel'])
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)

    def test_forged_native_grant_never_changes_protected_state(self):
        self.ready();before=self.source.read_view(self.object,self.now)['fence']
        forged=json.loads(json.dumps(self.f['cancel']));forged['proof']['signature']='0'*128
        with self.assertRaises(AdmissionRejected):self.mutate('grant',forged)
        self.assertEqual(self.source.read_view(self.object,self.now)['fence'],before)

    def test_runtime_loader_requires_existing_private_checkpoints(self):
        root=Path(self.tmp.name); key=root/'storage-key';key.write_text('fixture-key');key.chmod(0o600)
        anchor=root/'freshness.db'
        for path in (self.path,anchor):path.chmod(0o600)
        binding=MediaSettings(UUID(self.tenant),'fixture-subject',self.owner,self.path,anchor,
                              'https://storage.example',key)
        _provisioned(binding)
        loaded=_source(binding)
        self.assertTrue(loaded.production_ready)
        self.assertEqual(loaded.tenant,self.tenant)
        key.chmod(0o644)
        with self.assertRaises(ValueError):_provisioned(binding)

    def test_native_owner_entrypoints_preserve_signed_admission(self):
        async def run():
            view=await self.source.owner_view(self.tenant,self.owner,self.object)
            self.assertEqual(view['at'],self.now)
            self.assertEqual(set(view['bindings']),{self.owner})
            self.assertTrue(await self.source.owner_mutate(self.tenant,self.owner,self.object,
                view['at'],view['fence'],'grant',self.f['grant']))
            with self.assertRaises(AdmissionRejected):
                await self.source.owner_view(self.tenant,'unbound-owner',self.object)
        asyncio.run(run())

    def test_native_publication_reservation_and_idempotent_commit(self):
        payload=b'private fixture bytes';digest=hashlib.sha256(payload).hexdigest()
        metadata={**self.f['wrap'],'record':digest,'digest':digest}
        view=self.source.read_view(self.object,self.now)
        permit=self.source.prepare_write(self.tenant,self.owner,self.object,self.now,view['fence'],metadata,digest,len(payload))
        self.now+=1
        self.assertTrue(self.source.commit_write(permit))
        view=self.source.read_view(self.object,self.now)
        version=view['objectVersion']
        repeated=self.source.prepare_write(self.tenant,self.owner,self.object,self.now,view['fence'],metadata,digest,len(payload))
        self.assertTrue(self.source.commit_write(repeated))
        self.assertEqual(self.source.read_view(self.object,self.now)['objectVersion'],version)

    def test_status_draft_waits_for_real_settlement_and_matches_native_signed_status(self):
        with self.assertRaises(AdmissionRejected):
            self.source._owner_status_view(self.tenant,self.owner,self.object,self.owner,lambda:None)
        self.now+=3600
        draft=self.source._owner_status_view(self.tenant,self.owner,self.object,self.owner,lambda:None)
        self.assertEqual(draft['status'],{k:v for k,v in self.f['status'].items() if k!='signature'})
        self.assertEqual(draft['ownerPub'],self.owner)
        self.source.mutate(self.tenant,self.owner,self.object,draft['at'],draft['fence'],'status',self.f['status'])
        self.assertTrue(self.source.commit(self.source.authorize(self.tenant,self.owner,self.object)))

    def test_owner_catalog_uses_native_identity_before_returning_object_ids(self):
        async def run():
            result=await self.source.owner_catalog(self.tenant,self.owner,0)
            self.assertEqual(result,{'at':self.now,'objects':[self.object],'nextPage':1})
        asyncio.run(run())


    def test_allocation_checks_real_current_owner_signature_before_consuming(self):
        from types import SimpleNamespace
        from media_source import encoded
        record=self.f['allocationRecord']
        policy={k:self.f['identity'][k] for k in ('jwks','policy','pinnedIss')}
        scope=SimpleNamespace(tenant=self.tenant,owner=self.owner,object=record['object'],
            ownership_digest=hashlib.sha256(encoded(record)).hexdigest(),
            policy_digest=hashlib.sha256(encoded(policy)).hexdigest())
        scope.claims=lambda:{'tenant':self.tenant,'owner':self.owner,'object':record['object']}
        proof=SimpleNamespace(scope=scope,allocation='01234567-89ab-cdef-0123-456789abcdef',issued_at=self.now,expires_at=self.now+60)
        def consume(value):
            return self.source.consume_allocation(self.tenant,self.owner,value,policy,self.now+7200,verify_grant=lambda at:proof)
        forged={**record,'sig':'A'*86}
        scope.ownership_digest=hashlib.sha256(encoded(forged)).hexdigest()
        with self.assertRaises(AdmissionRejected):consume(forged)
        scope.ownership_digest=hashlib.sha256(encoded(record)).hexdigest()
        request=self.source.prepare_allocation_request(self.tenant,self.owner,record,policy,self.now+7200,
            sign_request=lambda claims:encoded(claims))
        self.assertEqual(json.loads(request)['ownershipDigest'],scope.ownership_digest)
        self.assertTrue(consume(record))
        self.assertFalse(consume(record))

    def test_current_native_owner_roundtrip_through_authenticated_storage_issuer(self):
        import base64
        from types import SimpleNamespace
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from acl_service.allocation_protocol.media_allocation_request import AllocationRequestSigner
        from acl_service.allocation_protocol.media_allocation_grant import verify_allocation_request,canonical_message
        from acl_service.domain.media_allocation import AllocationBinding,canonical
        issuer_id=str(UUID(int=2));source_id=str(UUID(int=3))
        policy={k:self.f['identity'][k] for k in ('jwks','policy','pinnedIss')}
        digest=hashlib.sha256(canonical(policy)).hexdigest()
        source_key=Ed25519PrivateKey.from_private_bytes(b'\x07'*32)
        storage_key=Ed25519PrivateKey.from_private_bytes(b'\x08'*32)
        signer=AllocationRequestSigner(issuer=issuer_id,source=source_id,tenant=self.tenant,
            policy_digest=digest,key_id='source',signing_key=source_key)
        calls=[]
        async def issue(scope,request):
            verified=verify_allocation_request(request,expected=scope,keys={'source':source_key.public_key()},now=self.now)
            calls.append(verified)
            # Independent fixture issuer; durable issuance is covered in Core CI.
            claims={**scope.claims(),'version':1,'allocation':str(UUID(int=4)),
                    'issuedAt':self.now,'expiresAt':self.now+60}
            sig=base64.urlsafe_b64encode(storage_key.sign(canonical_message('storage',claims))).rstrip(b'=').decode()
            return canonical({'keyId':'storage','claims':claims,'signature':sig})
        binding=AllocationBinding(self.tenant,self.owner,self.source,SimpleNamespace(issue=issue),signer,
            issuer_id,source_id,policy,self.now+7200,{'storage':storage_key.public_key()})
        async def run():
            result=await binding.allocate(self.f['allocationRecord'])
            self.assertEqual(result,{'object':self.f['allocationRecord']['object'],'accepted':True})
            self.assertEqual(await binding.allocate(self.f['allocationRecord']),result)
            self.assertEqual(len(calls),2)
            self.assertEqual(self.source.read_view(self.f['allocationRecord']['object'],self.now)['snapshot'],{'entries':[]})
        asyncio.run(run())
