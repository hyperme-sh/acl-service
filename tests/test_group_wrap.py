"""Mock-only group wrap coordinator unit contracts."""
import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock,Mock
from acl_service.domain.group_wrap import (GroupKeyReadPermit,GroupWrapReadPermit,GroupWrapWritePermit,
    GroupWrapRejected,publish_group_wrap,deliver_group_wrap)

DATA=b'encrypted group key';DIGEST=hashlib.sha256(DATA).hexdigest()


class GroupWrapTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.now=100
        self.write=GroupWrapWritePermit('tenant','owner','same-group','set',DIGEST,len(DATA),'f'*64,103)
        self.key=GroupKeyReadPermit('tenant','reader','same-group','set',1,'a'*64,'epub','b'*64,'f'*64,102)
        self.read=GroupWrapReadPermit(self.key,DIGEST,len(DATA))
        self.authority=SimpleNamespace(prepare_group_wrap_write=AsyncMock(return_value=self.write),
            commit_group_wrap_write=AsyncMock(return_value=True),authorize_group_wrap_read=AsyncMock(return_value=self.read),
            commit_group_wrap_read=AsyncMock(return_value=True))
        self.bound=SimpleNamespace(create_or_reconcile=AsyncMock(return_value=DIGEST),read=AsyncMock(return_value=DATA))
        self.store=SimpleNamespace(tenant='tenant',for_group=Mock(return_value=self.bound))

    async def publish(self,**changes):
        values=dict(authority=self.authority,store=self.store,tenant='tenant',owner='owner',predicate='same-group',
            set_id='set',at=100,fence='f'*64,metadata={'digest':DIGEST},payload=DATA,clock=lambda:self.now)
        values.update(changes);return await publish_group_wrap(**values)

    async def deliver(self,**changes):
        values=dict(authority=self.authority,store=self.store,tenant='tenant',reader='reader',predicate='same-group',
            set_id='set',clock=lambda:self.now);values.update(changes);return await deliver_group_wrap(**values)

    async def test_publication_orders_reservation_storage_and_commit(self):
        calls=[]
        self.authority.prepare_group_wrap_write.side_effect=lambda *args:calls.append('prepare') or self.write
        self.bound.create_or_reconcile.side_effect=lambda *args:calls.append('store') or DIGEST
        self.authority.commit_group_wrap_write.side_effect=lambda *args:calls.append('commit') or True
        self.assertEqual(await self.publish(),DIGEST)
        self.assertEqual(calls,['prepare','store','commit'])
        self.store.for_group.assert_called_once_with('set')

    async def test_publication_refuses_bad_input_permit_storage_or_commit(self):
        for changes in [{'payload':'bad'},{'payload':b''},{'payload':b'x'*65537},{'tenant':'other'},
                        {'metadata':None},{'metadata':{'digest':'a'*64}}]:
            with self.assertRaises(GroupWrapRejected):await self.publish(**changes)
        for permit in [None,replace(self.write,owner='other'),replace(self.write,length=1),
                       replace(self.write,expires_at=True),replace(self.write,expires_at=100),replace(self.write,expires_at=104)]:
            self.authority.prepare_group_wrap_write.return_value=permit
            with self.assertRaises(GroupWrapRejected):await self.publish()
        self.authority.prepare_group_wrap_write.return_value=self.write
        self.bound.create_or_reconcile.return_value='wrong'
        with self.assertRaises(GroupWrapRejected):await self.publish()
        self.bound.create_or_reconcile.return_value=DIGEST
        self.authority.commit_group_wrap_write.return_value=1
        with self.assertRaises(GroupWrapRejected):await self.publish()
        self.authority.commit_group_wrap_write.return_value=True
        self.bound.create_or_reconcile.side_effect=lambda *args:setattr(self,'now',103) or DIGEST
        with self.assertRaises(GroupWrapRejected):await self.publish()
        self.now=100;self.bound.create_or_reconcile.side_effect=None
        self.authority.commit_group_wrap_write.side_effect=lambda *args:setattr(self,'now',103) or True
        with self.assertRaises(GroupWrapRejected):await self.publish()

    async def test_delivery_commits_after_exact_bytes_without_exposing_fence(self):
        def commit(permit):
            self.bound.read.assert_awaited_once();return True
        self.authority.commit_group_wrap_read.side_effect=commit
        result=await self.deliver()
        self.assertEqual((result.payload,result.key_commitment),(DATA,'b'*64))
        self.assertFalse(hasattr(result,'fence'))

    async def test_delivery_refuses_wrong_context_bytes_and_expiry(self):
        with self.assertRaises(GroupWrapRejected):await self.deliver(tenant='other')
        for permit in [None,replace(self.read,key=None),replace(self.read,length=True),replace(self.read,length=0),
                       replace(self.read,digest='bad'),*[replace(self.read,key=replace(self.key,**change)) for change in
                       [{'reader':'other'},{'epoch':True},{'epoch':0},{'reader_epub':''},{'expires_at':True},
                        {'expires_at':100},{'expires_at':103},{'revision_id':'bad'},{'key_commitment':'bad'}]]]:
            self.authority.authorize_group_wrap_read.return_value=permit
            with self.assertRaises(GroupWrapRejected):await self.deliver()
        self.authority.authorize_group_wrap_read.return_value=self.read
        for body in ['bad',b'',b'x'*len(DATA)]:
            self.bound.read.return_value=body
            with self.assertRaises(GroupWrapRejected):await self.deliver()
        self.bound.read.return_value=DATA
        self.authority.commit_group_wrap_read.return_value=1
        with self.assertRaises(GroupWrapRejected):await self.deliver()
        self.authority.commit_group_wrap_read.side_effect=lambda *args:setattr(self,'now',102) or True
        with self.assertRaises(GroupWrapRejected):await self.deliver()

    async def test_cancellation_propagates_and_never_commits(self):
        self.bound.read.side_effect=asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):await self.deliver()
        self.authority.commit_group_wrap_read.assert_not_awaited()
        self.bound.create_or_reconcile.side_effect=asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):await self.publish()
        self.authority.commit_group_wrap_write.assert_not_awaited()
