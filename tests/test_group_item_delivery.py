"""Mock-only joint group item delivery coordinator units."""
import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock,Mock
from acl_service.domain.group_item_delivery import GroupItemReadPermit,GroupItemDeliveryRejected,deliver_group_item_wrap
from acl_service.domain.group_wrap import GroupKeyReadPermit
from acl_service.domain.history_store import HistoryConflict

DATA=b'opaque item key wrap';DIGEST=hashlib.sha256(DATA).hexdigest()

class GroupItemDeliveryTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.now=100
        self.key=GroupKeyReadPermit('tenant','reader','same-group','set',3,'a'*64,'epub','b'*64,'c'*64,102)
        self.permit=GroupItemReadPermit(self.key,'object',2,'d'*64,'e'*64,DIGEST,len(DATA),'f'*64,102)
        self.authority=SimpleNamespace(authorize_group_item_read=AsyncMock(return_value=self.permit),commit_group_item_read=AsyncMock(return_value=True))
        self.bound=SimpleNamespace(read=AsyncMock(return_value=DATA))
        class Store:
            tenant='tenant'
            def for_object(inner,object):
                self.bound_object=object;return self.bound
        self.store=Store()

    async def deliver(self,**changes):
        values=dict(authority=self.authority,store=self.store,tenant='tenant',reader='reader',object='object',predicate='same-group',set_id='set',clock=lambda:self.now)
        values.update(changes);return await deliver_group_item_wrap(**values)

    async def test_commits_joint_authority_after_media_storage_and_returns_distinct_epochs(self):
        def commit(permit):
            self.assertEqual(permit,self.permit);self.bound.read.assert_awaited_once_with(DIGEST,DIGEST,cancel=cancel);return True
        cancel=Mock();self.authority.commit_group_item_read.side_effect=commit
        result=await self.deliver(cancel=cancel)
        self.assertEqual(self.bound_object,'object')
        self.assertEqual((result.payload,result.item_epoch,result.group_epoch),(DATA,2,3))
        self.assertEqual((result.item_digest,result.group_key_commitment),('e'*64,'b'*64))
        self.assertFalse(hasattr(result,'fence'));self.assertFalse(hasattr(result,'reader_epub'))
        self.assertEqual(cancel.call_count,3)

    async def test_bad_permits_refuse_before_storage(self):
        for value in [None,replace(self.permit,key=None),replace(self.permit,object='other'),
                      *[replace(self.permit,**change) for change in [{'item_epoch':True},{'item_epoch':0},{'item_epoch':9007199254740992},
                        {'length':True},{'length':0},{'length':65537},{'expires_at':True},{'expires_at':100},{'expires_at':103},
                        {'item_revision_id':'bad'},{'item_digest':'bad'},{'wrap_digest':'bad'},{'fence':'bad'}]],
                      *[replace(self.permit,key=replace(self.key,**change)) for change in [{'tenant':'other'},{'reader':'other'},
                        {'predicate':'named-circle'},{'set_id':'other'},{'epoch':True},{'epoch':0},{'expires_at':True},
                        {'expires_at':101},{'expires_at':103},{'revision_id':'bad'},{'key_commitment':'bad'},{'fence':'bad'}]]]:
            self.authority.authorize_group_item_read.return_value=value
            with self.assertRaises(GroupItemDeliveryRejected):await self.deliver()
        self.bound.read.assert_not_awaited();self.authority.commit_group_item_read.assert_not_awaited()
        self.authority.authorize_group_item_read.reset_mock()
        with self.assertRaises(GroupItemDeliveryRejected):await self.deliver(tenant='other')
        self.authority.authorize_group_item_read.assert_not_awaited()

    async def test_bad_bytes_expiry_and_commit_never_release_a_wrap(self):
        for body in ['bad',b'',b'x'*len(DATA)]:
            self.bound.read.return_value=body
            with self.assertRaises(GroupItemDeliveryRejected):await self.deliver()
        self.authority.commit_group_item_read.assert_not_awaited()
        self.bound.read.return_value=DATA
        self.authority.commit_group_item_read.return_value=1
        with self.assertRaises(GroupItemDeliveryRejected):await self.deliver()
        self.authority.commit_group_item_read.return_value=True
        self.bound.read.side_effect=lambda *a,**k:setattr(self,'now',102) or DATA
        with self.assertRaises(GroupItemDeliveryRejected):await self.deliver()
        self.now=100;self.bound.read.side_effect=None
        self.authority.commit_group_item_read.side_effect=lambda *a:setattr(self,'now',102) or True
        with self.assertRaises(GroupItemDeliveryRejected):await self.deliver()

    async def test_cancellation_and_source_conflict_propagate(self):
        self.bound.read.side_effect=asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):await self.deliver()
        self.authority.commit_group_item_read.assert_not_awaited()
        self.bound.read.side_effect=None
        self.authority.commit_group_item_read.side_effect=HistoryConflict('changed')
        with self.assertRaises(HistoryConflict):await self.deliver()
        self.authority.commit_group_item_read.side_effect=None
        def cancelled():raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):await self.deliver(cancel=cancelled)


class GroupItemPublicationTests(IsolatedAsyncioTestCase):
    def setUp(self):
        from acl_service.domain.group_item_delivery import GroupItemWritePermit
        self.now=100
        self.permit=GroupItemWritePermit('tenant','owner','object','same-group','set','reader',DIGEST,len(DATA),'f'*64,102)
        self.authority=SimpleNamespace(prepare_group_item_write=AsyncMock(return_value=self.permit),commit_group_item_write=AsyncMock(return_value=True))
        self.bound=SimpleNamespace(create_or_reconcile=AsyncMock(return_value=DIGEST))
        class Store:
            tenant='tenant'
            def for_object(inner,object):self.bound_object=object;return self.bound
        self.store=Store()

    async def publish(self,**changes):
        from acl_service.domain.group_item_delivery import publish_group_item_wrap
        args=dict(authority=self.authority,store=self.store,tenant='tenant',owner='owner',object='object',predicate='same-group',
            set_id='set',reader='reader',at=100,fence='fence',metadata={'digest':DIGEST},payload=DATA,clock=lambda:self.now)
        args.update(changes);return await publish_group_item_wrap(**args)

    async def test_reserves_publishes_to_item_allocation_then_commits(self):
        def commit(permit):
            self.assertEqual(permit,self.permit);self.bound.create_or_reconcile.assert_awaited_once_with(DIGEST,DATA);return True
        self.authority.commit_group_item_write.side_effect=commit
        self.assertEqual(await self.publish(),DIGEST);self.assertEqual(self.bound_object,'object')
        self.authority.prepare_group_item_write.assert_awaited_once_with('tenant','owner','object','same-group','set','reader',100,'fence',{'digest':DIGEST},len(DATA))

    async def test_invalid_input_or_permit_never_uploads(self):
        for change in [{'payload':None},{'payload':b''},{'payload':b'x'*65537},{'tenant':'other'},{'metadata':[]},{'metadata':{'digest':'other'}}]:
            with self.assertRaises(GroupItemDeliveryRejected):await self.publish(**change)
        self.authority.prepare_group_item_write.assert_not_awaited()
        for permit in [None,*[replace(self.permit,**change) for change in [{'tenant':'other'},{'owner':'other'},{'object':'other'},
            {'predicate':'other'},{'set_id':'other'},{'reader':'other'},{'digest':'a'*64},{'length':True},{'length':1},
            {'expires_at':True},{'expires_at':100},{'expires_at':103},{'fence':'bad'},{'fence':None}]]]:
            self.authority.prepare_group_item_write.return_value=permit
            with self.assertRaises(GroupItemDeliveryRejected):await self.publish()
        self.bound.create_or_reconcile.assert_not_awaited();self.authority.commit_group_item_write.assert_not_awaited()

    async def test_storage_commit_and_expiry_fail_closed(self):
        self.bound.create_or_reconcile.return_value='other'
        with self.assertRaises(GroupItemDeliveryRejected):await self.publish()
        self.authority.commit_group_item_write.assert_not_awaited()
        self.bound.create_or_reconcile.return_value=DIGEST
        self.authority.commit_group_item_write.return_value=1
        with self.assertRaises(GroupItemDeliveryRejected):await self.publish()
        self.authority.commit_group_item_write.return_value=True
        self.bound.create_or_reconcile.side_effect=lambda *a:setattr(self,'now',102) or DIGEST
        with self.assertRaises(GroupItemDeliveryRejected):await self.publish()
        self.now=100;self.bound.create_or_reconcile.side_effect=None
        self.authority.commit_group_item_write.side_effect=lambda *a:setattr(self,'now',102) or True
        with self.assertRaises(GroupItemDeliveryRejected):await self.publish()
        self.now=100;self.authority.commit_group_item_write.side_effect=HistoryConflict('changed')
        with self.assertRaises(HistoryConflict):await self.publish()
        self.bound.create_or_reconcile.side_effect=asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):await self.publish()
