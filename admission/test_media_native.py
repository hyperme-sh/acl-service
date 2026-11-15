"""Actual enrolled identity + Rust + checkpoint contract, CI container only."""
import hashlib
import asyncio
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from media_source import MediaSource
from acl_service.infrastructure.epoch_verifier import GroupEpochConfigVerifier
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

    def item_group_setup(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from group_source import GroupSource
        from group_key_source import GroupKeySource
        from group_membership import GroupMembership
        from group_item_source import GroupItemSource
        from group_item_grants import GroupItemGrants
        # This fixture journal isolates PostgreSQL IO; identities, group checks,
        # signatures, media transactions and checkpoints use their real adapters.
        source=object.__new__(GroupSource)
        source.media=self.source;source.store=self.store;source.journal=Mock()
        retained={'row':None}
        source.journal.read.side_effect=lambda *args:retained['row']
        def save(db,predicate,set_id,expected,document):
            self.assertIs(expected,retained['row'])
            retained['row']=SimpleNamespace(revision=1 if expected is None else expected.revision+1,
                nonce=b'n'*32,document=json.dumps(document).encode())
            return retained['row']
        source.journal.write.side_effect=save
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,self.object,self.now)
            doc['policyUntil']=self.now+10800
            self.source._save(db,self.object,row,doc)
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        args=(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        view=source.creation_view(*args);source.create(*args,view['fence'],policy)
        members=GroupMembership(source)
        margs=(self.tenant,self.owner,self.now,predicate,set_id,self.owner)
        for role,record in [('set',self.f['groupInvitations'][0]),('member',self.f['groupMemberRows'][0])]:
            view=members.view(*margs,role,1);members.append(*margs,role,view['fence'],record)
        current=self.source.group_authority_view(self.tenant,self.owner,self.object,self.now)
        self.source.append_group(self.tenant,self.owner,self.object,self.now,current['fence'],predicate,set_id,
            [{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']},self.f['groupEdges'][0]])
        self.now+=3600
        self.mutate('status',self.f['groupOwnerStatus'])
        return GroupItemGrants(GroupItemSource(GroupKeySource(source))),members,predicate,set_id

    def test_native_group_item_grant_is_independent_and_cancel_survives_membership_loss(self):
        grants,members,predicate,set_id=self.item_group_setup()
        args=(self.tenant,self.owner,self.object,predicate,set_id)
        before=self.source.read_view(self.object,self.now)['snapshot']
        view=grants.view(*args,self.owner)
        self.assertEqual(view['grant'],self.f['itemGroupGrant']['claims'])
        malformed=json.loads(json.dumps(self.f['itemGroupGrant']))
        malformed['proof']['signature']='0'*128
        with self.assertRaises(AdmissionRejected):grants.append(*args,self.now,view['fence'],malformed)
        self.assertEqual(grants.state(*args,self.f['itemGroupGrant'])['state'],'absent')
        self.assertTrue(grants.append(*args,self.now,view['fence'],self.f['itemGroupGrant']))
        self.assertEqual(self.source.read_view(self.object,self.now)['snapshot'],before)
        margs=(self.tenant,self.owner,self.now,predicate,set_id,self.owner)
        withdrawal=members.view(*margs,'member',0)
        members.append(*margs,'member',withdrawal['fence'],self.f['itemMemberWithdraw'])
        with self.assertRaises(AdmissionRejected):grants.view(*args,self.owner)
        cancel=grants.view(*args,self.owner,True)
        self.assertEqual(cancel['grant'],self.f['itemGroupCancel']['claims'])
        self.assertTrue(grants.append(*args,self.now,cancel['fence'],self.f['itemGroupCancel']))
        self.now+=5
        self.assertEqual(grants.state(*args,self.f['itemGroupGrant'])['state'],'applied')
        self.assertEqual(grants.state(*args,self.f['itemGroupCancel'])['state'],'applied')
        self.assertEqual(self.source.read_view(self.object,self.now)['snapshot'],before)

    def test_native_group_item_epoch_admission_is_atomic_and_exactly_recoverable(self):
        grants,_,predicate,set_id=self.item_group_setup()
        args=(self.tenant,self.owner,self.object,predicate,set_id)
        view=grants.view(*args,self.owner)
        grants.append(*args,self.now,view['fence'],self.f['itemGroupGrant'])
        # The old read status is stale after the grant write; owner maintenance
        # still prepares signed metadata without returning a read permit.
        with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)
        items=grants.items;plan=items.epoch_view(*args);command=self.f['itemEpochCommand']
        self.assertEqual(plan['snapshot'],command['document']['snapshot'])
        self.assertEqual(plan['grants'],[row['claims'] for row in command['grants']])
        before=self.source.read_view(self.object,self.now)
        forged=json.loads(json.dumps(command));forged['finalization']['signature']='0'*128
        with self.assertRaises(AdmissionRejected):items.append_epoch(*args,self.now,plan['fence'],forged)
        self.assertEqual(self.source.read_view(self.object,self.now),before)
        self.assertEqual(items.epoch_state(*args,command)['state'],'absent')
        self.assertTrue(items.append_epoch(*args,self.now,plan['fence'],command))
        self.assertEqual(items.epoch_state(*args,command)['state'],'applied')
        after=self.source.read_view(self.object,self.now)
        self.assertEqual(after['objectVersion'],before['objectVersion']+1)
        self.now+=5
        self.assertTrue(items.append_epoch(*args,self.now,'unused',command))
        self.assertEqual(self.source.read_view(self.object,self.now)['objectVersion'],after['objectVersion'])
        # Admission alone must never release an item key or bypass settlement.
        from unittest.mock import patch
        with patch('group_source.GroupSource',return_value=items.keys.source):
            with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)

    def test_native_direct_reader_uses_combined_epoch_and_current_group_checkpoint(self):
        from unittest.mock import patch
        grants,members,predicate,set_id=self.item_group_setup()
        args=(self.tenant,self.owner,self.object,predicate,set_id)
        view=grants.view(*args,self.owner)
        grants.append(*args,self.now,view['fence'],self.f['itemGroupGrant'])
        self.mutate('status',self.f['itemEpochOwnerStatus'])
        items=grants.items;plan=items.epoch_view(*args)
        items.append_epoch(*args,self.now,plan['fence'],self.f['itemEpochCommand'])
        self.now+=3600
        with patch('group_source.GroupSource',return_value=items.keys.source):
            with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)
            self.mutate('wrap',{**self.f['wrap'],'epoch':2,'revisionId':self.f['itemEpochCommand']['document']['manifest']['revisionId']})
            self.mutate('status',self.f['combinedOwnerStatus'])
            permit=self.source.authorize(self.tenant,self.owner,self.object)
            self.assertEqual(permit.epoch,2)
            self.assertTrue(self.source.commit(permit))
            margs=(self.tenant,self.owner,self.now,predicate,set_id,self.owner)
            withdrawal=members.view(*margs,'member',0)
            members.append(*margs,'member',withdrawal['fence'],self.f['combinedMemberWithdraw'])
            with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)
            with self.assertRaises(AdmissionRejected):self.source.commit(permit)

    def test_native_group_item_signed_fork_freezes_only_group_journal(self):
        grants,_,predicate,set_id=self.item_group_setup()
        args=(self.tenant,self.owner,self.object,predicate,set_id)
        view=grants.view(*args,self.owner)
        grants.append(*args,self.now,view['fence'],self.f['itemGroupGrant'])
        with self.assertRaises(AdmissionRejected):grants.append(*args,self.now,view['fence'],self.f['itemGroupFork'])
        self.assertTrue(grants.state(*args,self.f['itemGroupGrant'])['frozen'])
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,self.object,self.now)
            self.assertEqual(doc['frozen'],[])
            self.assertEqual(doc['grants'],[self.f['grant']|{'ownerPub':self.owner}])
            self.assertEqual(len(doc['groupItemGrants']['conflicts']),1)

    def test_native_independent_group_key_history_and_settlement(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from group_source import GroupSource
        from group_key_source import GroupKeySource
        from group_membership import GroupMembership
        source=object.__new__(GroupSource)
        source.media=self.source;source.store=self.store;source.journal=Mock()
        retained={'row':None}
        source.journal.read.side_effect=lambda *args:retained['row']
        def save(db,predicate,set_id,expected,document):
            self.assertIs(expected,retained['row'])
            retained['row']=SimpleNamespace(revision=1 if expected is None else expected.revision+1,
                nonce=b'n'*32,document=json.dumps(document).encode())
            return retained['row']
        source.journal.write.side_effect=save
        config=self.f['groupPolicy'];predicate=config['predicate'];group=config['setId']
        create_args=(self.tenant,self.owner,self.object,self.now,predicate,group)
        creation=source.creation_view(*create_args)
        source.create(*create_args,creation['fence'],config)
        keys=GroupKeySource(source)
        args=(self.tenant,self.owner,self.now,predicate,group)
        view=keys.view(*args);command=self.f['groupKeyEpoch']
        self.assertEqual(view['snapshot'],command['document']['snapshot'])
        malformed=json.loads(json.dumps(command));malformed['document']['manifest']['signature']='0'*128
        with self.assertRaises(AdmissionRejected):keys.append(*args,view['fence'],malformed)
        self.assertTrue(keys.append(*args,view['fence'],command))
        state=keys.state(*args,command);self.assertEqual(state['state'],'applied')
        self.assertTrue(keys.append(*args,state['fence'],command))
        def selected():
            with self.store._transaction(write=False) as db:
                _,doc,snapshot,policy=keys._load(db,self.tenant,self.owner,self.now,predicate,group)
                return keys.native.matches_settled(json.dumps(keys._history(doc,snapshot,policy,self.now)).encode())
        self.assertFalse(selected())
        self.now+=3600
        self.assertTrue(selected())
        # A current membership change invalidates the old group key snapshot.
        self.now-=3600
        members=GroupMembership(source)
        member_args=(*args,self.owner)
        invite=members.view(*member_args,'set',1)
        members.append(*member_args,'set',invite['fence'],self.f['groupInvitations'][0])
        join=members.view(*member_args,'member',1)
        members.append(*member_args,'member',join['fence'],self.f['groupMemberRows'][0])
        self.now+=3600
        self.assertFalse(selected())

    def test_native_independent_group_creation_requires_current_owner_signature(self):
        from unittest.mock import Mock
        from group_source import GroupSource
        # This contract exercises the real history and Rust adapters. The
        # journal's PostgreSQL atomicity is covered separately in CI.
        source=object.__new__(GroupSource)
        source.media=self.source;source.store=self.store
        source.journal=Mock();source.journal.read.return_value=None
        config=self.f['groupPolicy']
        args=(self.tenant,self.owner,self.object,self.now,config['predicate'],config['setId'])
        view=source.creation_view(*args)
        self.assertEqual(view['context']['ownerPub'],self.owner)
        self.assertTrue(source.create(*args,view['fence'],config))
        saved=source.journal.write.call_args.args[4]
        self.assertEqual(saved['rows'],[])
        self.assertEqual(saved['epochs'],[])
        self.assertEqual(saved['configs'],[config])
        source.journal.write.reset_mock()
        with self.assertRaises(AdmissionRejected):
            source.create(*args,view['fence'],{**config,'signature':'0'*128})
        with self.assertRaises(AdmissionRejected):
            source.create(*args,view['fence'],{**config,'setId':config['setId'][:-1]+'f'})
        source.journal.write.assert_not_called()

    def test_native_independent_group_invitation_acceptance_and_withdrawal(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from group_source import GroupSource
        from group_membership import GroupMembership
        source=object.__new__(GroupSource)
        source.media=self.source;source.store=self.store;source.journal=Mock()
        retained={'row':None}
        source.journal.read.side_effect=lambda *args:retained['row']
        def save(db,predicate,set_id,expected,document):
            self.assertIs(expected,retained['row'])
            retained['row']=SimpleNamespace(revision=1 if expected is None else expected.revision+1,
                nonce=b'n'*32,document=json.dumps(document).encode())
            return retained['row']
        source.journal.write.side_effect=save
        config=self.f['groupPolicy'];predicate=config['predicate'];group=config['setId']
        create_args=(self.tenant,self.owner,self.object,self.now,predicate,group)
        view=source.creation_view(*create_args)
        source.create(*create_args,view['fence'],config)
        members=GroupMembership(source)
        source.journal.scopes.return_value=[(predicate,group)]
        self.assertEqual(members.catalog(self.tenant,self.owner,self.now,0)['groups'][0]['active'],False)
        args=(self.tenant,self.owner,self.now,predicate,group,self.owner)
        with self.assertRaises(AdmissionRejected):members.view(*args,'member',1)
        invite=members.view(*args,'set',1)
        members.append(*args,'set',invite['fence'],self.f['groupInvitations'][0])
        join=members.view(*args,'member',1)
        self.assertEqual(join['draft']['hamState'],2)
        members.append(*args,'member',join['fence'],self.f['groupMemberRows'][0])
        self.assertEqual(members.state(*args,'member',self.f['groupMemberRows'][0])['state'],'applied')
        self.assertTrue(members.catalog(self.tenant,self.owner,self.now,0)['groups'][0]['active'])
        withdraw=members.view(*args,'member',0)
        members.append(*args,'member',withdraw['fence'],self.f['groupMemberRows'][1])
        with self.store._transaction(write=False) as db:
            doc=json.loads(retained['row'].document)
            state=members._state(db,doc,self.now,predicate,group,self.owner,doc['rows'])
            self.assertEqual(state['state']['stated'],0)
        # Reconciliation records the old command without restoring membership.
        self.assertEqual(members.state(*args,'member',self.f['groupMemberRows'][0])['state'],'applied')
        self.assertFalse(members.catalog(self.tenant,self.owner,self.now,0)['groups'][0]['active'])
        self.assertEqual(doc['epochs'],[])
        self.assertEqual(doc['wraps'],[])

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

    def test_native_deletion_invalidates_issued_permit_and_refuses_scope_changes(self):
        from cryptography.hazmat.primitives.asymmetric import ec,utils
        from cryptography.hazmat.primitives import hashes
        permit=self.ready()
        view=self.source.deletion_view(self.tenant,self.owner,self.object)
        claims=view['claims']
        message=b'SOCIACL_PRIVATE_MEDIA_DELETE_V1\n'+json.dumps([claims[k] for k in
            ('tenant','object','owner','objectVersion','fence','issuedAt','expiresAt')],separators=(',',':')).encode()
        signature=ec.derive_private_key(1,ec.SECP256R1()).sign(message,ec.ECDSA(hashes.SHA256()))
        r,s=utils.decode_dss_signature(signature)
        order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        signature=(r.to_bytes(32,'big')+min(s,order-s).to_bytes(32,'big')).hex()
        proof={'deletionBytes':message.hex(),'signature':signature}
        with self.assertRaises(AdmissionRejected):
            self.source.delete(self.tenant,self.owner,self.object,self.now,{**proof,'signature':'0'*128})
        command=self.source.delete(self.tenant,self.owner,self.object,self.now,proof)
        self.assertEqual(len(command),64)
        with self.assertRaises(AdmissionRejected):self.source.read_view(self.object,self.now)
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.now+=1
        self.assertEqual(self.source.delete(self.tenant,self.owner,self.object,self.now-1,proof),command)

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

    def test_upload_reconciliation_reads_current_protected_state_without_delivery(self):
        before=self.source.read_view(self.object,self.now)['fence']
        for operation,payload in [('grant',self.f['grant']),('epoch',self.f['epoch']),('wrap',self.f['wrap'])]:
            result=asyncio.run(self.source.owner_upload_state(self.tenant,self.owner,self.object,operation,payload))
            self.assertEqual(result,{'at':self.now,'state':'applied'})
        self.assertEqual(self.source.read_view(self.object,self.now)['fence'],before)
        with self.assertRaises(AdmissionRejected):self.source.authorize(self.tenant,self.owner,self.object)
        with self.assertRaises(AdmissionRejected):
            asyncio.run(self.source.owner_upload_state(self.tenant,'foreign',self.object,'epoch',self.f['epoch']))
        with self.assertRaises(AdmissionRejected):
            asyncio.run(self.source.owner_upload_state(str(UUID(int=1)),self.owner,self.object,'epoch',self.f['epoch']))
        changed=json.loads(json.dumps(self.f['epoch']));changed['finalization']['signature']='forged'
        self.assertEqual(asyncio.run(self.source.owner_upload_state(self.tenant,self.owner,self.object,'epoch',changed))['state'],'conflict')
        backup=self.path.read_bytes();self.mutate('grant',self.f['cancel'])
        self.assertEqual(asyncio.run(self.source.owner_upload_state(self.tenant,self.owner,self.object,'grant',self.f['grant']))['state'],'conflict')
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):
            asyncio.run(self.source.owner_upload_state(self.tenant,self.owner,self.object,'epoch',self.f['epoch']))


    def test_group_policy_native_adapter_uses_independent_owner_scope(self):
        policy=self.f['groupPolicy']
        ids=self.source.read_view(self.object,self.now)
        expected={'owner':self.owner,'ownerPub':ids['bindings'][self.owner]['pub'],
                  'setId':self.object.replace('media_','set_'),'predicate':'same-group',
                  'settleWindowMs':3600000,'configRevision':2}
        verifier=GroupEpochConfigVerifier()
        raw=json.dumps(policy).encode()
        self.assertTrue(verifier.matches_config(raw,json.dumps(expected).encode()))
        for field,value in [('owner','other'),('ownerPub','bad'),('setId','other'),('predicate','named-circle'),
                            ('settleWindowMs',7200000),('configRevision',3)]:
            self.assertFalse(verifier.matches_config(raw,json.dumps({**expected,field:value}).encode()))
        duplicate=raw[:-1]+b',"configRevision":2}'
        self.assertFalse(verifier.matches_config(duplicate,json.dumps(expected).encode()))

    def test_protected_group_policy_uses_current_native_owner_and_checkpoint(self):
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        view=self.source.group_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        rows=[{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']}]
        self.source.append_group(self.tenant,self.owner,self.object,self.now,view['fence'],predicate,set_id,rows)
        view=self.source.group_policy_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        self.assertEqual(view['context'],{'owner':self.owner,'ownerPub':self.owner,'setId':set_id,'predicate':predicate})
        self.assertIsNone(view['config'])
        backup=self.path.read_bytes()
        self.source.append_group_policy(self.tenant,self.owner,self.object,self.now,view['fence'],predicate,set_id,policy)
        current=self.source.group_policy_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        self.assertEqual(current['config'],policy)
        self.assertEqual(self.source._group_policy_digest(policy),self.f['groupPolicyDigest'])
        with self.assertRaises(AdmissionRejected):
            self.source.append_group_policy(self.tenant,self.owner,self.object,self.now,current['fence'],predicate,set_id,{**policy,'settleWindowMs':7200000})
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):
            self.source.group_policy_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)

    def test_atomic_group_authority_preserves_native_edge_cancellation_and_direct_snapshot(self):
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        self.mutate('grant',self.f['grant'])
        view=lambda:self.source.group_authority_view(self.tenant,self.owner,self.object,self.now)
        first=view()
        rows=[{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']},self.f['groupEdges'][0]]
        self.source.append_group(self.tenant,self.owner,self.object,self.now,first['fence'],predicate,set_id,rows)
        self.source.append_group_policy(self.tenant,self.owner,self.object,self.now,view()['fence'],predicate,set_id,policy)
        live=view()
        self.assertEqual(live['policy']['config'],policy)
        self.assertEqual(live['projection']['snapshot']['objectSet']['stated'],1)
        self.assertEqual(live['direct'],first['direct'])
        self.assertEqual(set(live['bindings']),{self.owner})
        self.source.append_group(self.tenant,self.owner,self.object,self.now,live['fence'],predicate,set_id,[self.f['groupEdges'][1]])
        cancelled=view()
        self.assertEqual(cancelled['projection']['snapshot']['objectSet']['stated'],0)
        self.assertEqual(cancelled['projection']['snapshot']['objectSet']['hamState'],2)
        self.assertEqual(cancelled['projection']['members'],[])
        self.assertEqual(cancelled['direct'],first['direct'])
        self.assertGreater(cancelled['objectVersion'],live['objectVersion'])

    def test_native_consent_requires_invitation_even_for_set_owner(self):
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        view=lambda:self.source.group_consent_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        with self.assertRaises(AdmissionRejected):view()
        fence=self.source.group_authority_view(self.tenant,self.owner,self.object,self.now)['fence']
        rows=[{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']},self.f['groupInvitations'][0]]
        self.source.append_group(self.tenant,self.owner,self.object,self.now,fence,predicate,set_id,rows)
        prepared=view()
        self.assertIsNone(prepared['consent']['state']['memberAssent'])
        self.assertEqual(prepared['consent']['state']['stated'],0)
        self.assertEqual(prepared['consent']['draft']['member'],self.owner)
        self.assertEqual(prepared['consent']['draft']['role'],'member')
        self.assertEqual(prepared['consent']['draft']['hamState'],2)
        self.assertEqual(view()['fence'],prepared['fence'])
        self.source.append_group(self.tenant,self.owner,self.object,self.now,prepared['fence'],predicate,set_id,[self.f['groupInvitations'][1]])
        with self.assertRaises(AdmissionRejected):view()

    def test_native_member_consent_retry_and_withdrawal_after_invitation_removal(self):
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        owner_view=lambda:self.source.group_authority_view(self.tenant,self.owner,self.object,self.now)
        before=owner_view()['direct']
        rows=[{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']},self.f['groupInvitations'][0]]
        self.source.append_group(self.tenant,self.owner,self.object,self.now,owner_view()['fence'],predicate,set_id,rows)
        join,withdraw=self.f['groupMemberRows']
        self.now+=1  # Signing and fresh-fence reconciliation may cross a second.
        check=lambda row:asyncio.run(self.source.member_group_append_state(self.tenant,self.owner,self.object,predicate,set_id,row))
        append=lambda row,fence:asyncio.run(self.source.member_append_group(self.tenant,self.owner,self.object,self.now,fence,predicate,set_id,row))
        pending=check(join);self.assertEqual(pending['state'],'absent')
        self.assertTrue(append(join,pending['fence']))
        applied=check(join);self.assertEqual(applied['state'],'applied')
        self.assertTrue(append(join,applied['fence']));self.assertEqual(check(join)['fence'],applied['fence'])
        self.source.append_group(self.tenant,self.owner,self.object,self.now,applied['fence'],predicate,set_id,[self.f['groupInvitations'][1]])
        with self.assertRaises(AdmissionRejected):self.source.group_consent_view(self.tenant,self.owner,self.object,self.now,predicate,set_id)
        view=asyncio.run(self.source.member_group_withdrawal_view(self.tenant,self.owner,self.object,predicate,set_id))
        self.assertEqual(view['consent']['draft']['hamState'],2)
        self.assertTrue(append(withdraw,view['fence']))
        self.assertEqual(check(withdraw)['state'],'applied')
        self.assertEqual(owner_view()['direct'],before)
        with self.assertRaises(AdmissionRejected):append(self.f['groupInvitations'][0],check(withdraw)['fence'])
        malformed=json.loads(json.dumps(join));malformed['record']['sig']='a'*128
        with self.assertRaises(AdmissionRejected):check(malformed)

    def test_native_group_append_reconciliation_never_writes_or_hides_withdrawal(self):
        policy=self.f['groupPolicy'];predicate=policy['predicate'];set_id=policy['setId']
        rows=[{'kind':'object','soul':self.object,'record':self.f['groupObjectRecord']},self.f['groupEdges'][0]]
        check=lambda batch:self.source.group_append_state(self.tenant,self.owner,self.object,self.now,predicate,set_id,batch)
        pending=check(rows);self.assertEqual(pending['state'],'absent')
        self.source.append_group(self.tenant,self.owner,self.object,self.now,pending['fence'],predicate,set_id,rows)
        self.assertEqual(check(rows)['state'],'applied')
        boolean=json.loads(json.dumps(rows));boolean[1]['record']['stated']=True
        with self.assertRaises(AdmissionRejected):check(boolean)
        held=check(rows)
        with self.assertRaises(AdmissionRejected):
            self.source.append_group(self.tenant,self.owner,self.object,self.now,held['fence'],predicate,set_id,boolean)
        self.assertEqual(check(rows),held)
        withdrawal=[self.f['groupEdges'][1]];pending=check(withdrawal)
        current=lambda:self.source.group_object_view(self.tenant,self.owner,self.object,self.now)['projection']['snapshot']['objectSet']['stated']
        self.assertEqual(pending['state'],'absent');self.assertEqual(current(),1)
        self.source.append_group(self.tenant,self.owner,self.object,self.now,pending['fence'],predicate,set_id,withdrawal)
        self.assertEqual(check(withdrawal)['state'],'applied');self.assertEqual(current(),0)
        self.assertEqual(check(rows)['state'],'applied')  # Retention does not revive the earlier edge.
        bad=json.loads(json.dumps(rows));bad[1]['record']['sig']='invalid'
        with self.assertRaises(AdmissionRejected):check(bad)
