"""Pure mocked owner maintenance byte-delivery units."""
import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock,Mock
from acl_service.domain.group_owner_wrap import GroupOwnerWrapPermit,OwnerWrapRejected,deliver_owner_wrap
from acl_service.domain.history_store import HistoryConflict

class OwnerWrapTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.now=100;self.data=b'opaque';self.digest=hashlib.sha256(self.data).hexdigest()
        self.permit=GroupOwnerWrapPermit('tenant','owner','object','same-group','set',self.digest,self.digest,1,'a'*64,'owner-e','b'*64,'c'*64,'d'*64,102)
        self.authority=SimpleNamespace(authorize_group_owner_wrap=AsyncMock(return_value=self.permit),commit_group_owner_wrap=AsyncMock(return_value=True))
        self.bound=SimpleNamespace(read=AsyncMock(return_value=self.data))
        class Store:
            tenant='tenant'
            def for_object(inner,object):self.selected=object;return self.bound
        self.store=Store()
    async def deliver(self,**changes):
        values=dict(authority=self.authority,store=self.store,tenant='tenant',owner='owner',object='object',predicate='same-group',set_id='set',clock=lambda:self.now);values.update(changes)
        return await deliver_owner_wrap(**values)
    async def test_rechecks_owner_authority_after_allocated_storage(self):
        self.authority.commit_group_owner_wrap.side_effect=lambda permit:self.bound.read.await_count==1
        result=await self.deliver();self.assertEqual(result.payload,self.data);self.assertEqual(self.selected,'object')
        self.assertEqual(result.key_commitment,'b'*64);self.assertFalse(hasattr(result,'fence'))
    async def test_permit_and_generic_storage_refuse_before_read(self):
        for permit in [None,replace(self.permit,owner='other'),replace(self.permit,epoch=True),replace(self.permit,epoch=0),
                replace(self.permit,expires_at=100),replace(self.permit,expires_at=103),replace(self.permit,reader_epub=''),replace(self.permit,digest='bad')]:
            self.authority.authorize_group_owner_wrap.return_value=permit
            with self.assertRaises(OwnerWrapRejected):await self.deliver()
        self.bound.read.assert_not_awaited();self.authority.authorize_group_owner_wrap.reset_mock()
        for store in [SimpleNamespace(tenant='tenant',read=AsyncMock()),SimpleNamespace(tenant='other')]:
            with self.assertRaises(OwnerWrapRejected):await self.deliver(store=store)
        self.authority.authorize_group_owner_wrap.assert_not_awaited()
    async def test_storage_and_commit_failures_never_return_bytes(self):
        for data in [b'',b'changed','not bytes',b'a'*65537]:
            self.bound.read.return_value=data
            with self.assertRaises(OwnerWrapRejected):await self.deliver()
        self.authority.commit_group_owner_wrap.assert_not_awaited();self.bound.read.return_value=self.data
        self.authority.commit_group_owner_wrap.return_value=1
        with self.assertRaises(OwnerWrapRejected):await self.deliver()
        self.authority.commit_group_owner_wrap.side_effect=HistoryConflict('changed')
        with self.assertRaises(HistoryConflict):await self.deliver()
        def expires(permit):self.now=102;return True
        self.authority.commit_group_owner_wrap.side_effect=expires
        with self.assertRaises(OwnerWrapRejected):await self.deliver()
    async def test_cancellation_propagates(self):
        def cancel():raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):await self.deliver(cancel=cancel)
