"""Isolated publication orchestration units: no HTTP, database or native calls."""
import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock
from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.private_wrap_publication import (
    WrapWritePermit, WrapPublicationRejected, publish_private_wrap,
)

BODY=b'private encrypted wrap';DIGEST=hashlib.sha256(BODY).hexdigest()


class PublicationUnits(IsolatedAsyncioTestCase):
    def setup_case(self):
        self.now=100
        self.permit=WrapWritePermit('tenant','owner','object',DIGEST,DIGEST,len(BODY),'fence',103)
        self.authority=SimpleNamespace(prepare_wrap_write=AsyncMock(return_value=self.permit),commit_wrap_write=AsyncMock(return_value=True))
        self.store=SimpleNamespace(tenant='tenant',create_or_reconcile=AsyncMock(return_value=DIGEST))

    async def publish(self,payload=BODY):
        return await publish_private_wrap(self.authority,self.store,'tenant','owner','object',100,'fence',{},payload,clock=lambda:self.now)

    async def test_reservation_precedes_storage_and_exact_permit_commit(self):
        self.setup_case();order=[]
        async def prepare(*args):order.append('reserve');return self.permit
        async def create(*args):order.append('store');return DIGEST
        async def commit(permit):order.append('commit');self.assertIs(permit,self.permit);return True
        self.authority.prepare_wrap_write.side_effect=prepare
        self.store.create_or_reconcile.side_effect=create
        self.authority.commit_wrap_write.side_effect=commit
        self.assertEqual(await self.publish(),DIGEST)
        self.assertEqual(order,['reserve','store','commit'])

    async def test_invalid_payload_tenant_and_reservation_never_upload(self):
        for value in [b'',b'x'*65537,'not bytes']:
            self.setup_case()
            with self.assertRaises(WrapPublicationRejected):await self.publish(value)
            self.store.create_or_reconcile.assert_not_awaited()
        self.setup_case();self.store.tenant='other'
        with self.assertRaises(WrapPublicationRejected):await self.publish()
        self.store.create_or_reconcile.assert_not_awaited()
        for changes in [{'owner':'other'},{'object':'other'},{'digest':'a'*64},{'record':'a'*64},{'tenant':'other'},{'length':1},{'expires_at':100},{'expires_at':104}]:
            self.setup_case();self.authority.prepare_wrap_write.return_value=replace(self.permit,**changes)
            with self.assertRaises(WrapPublicationRejected):await self.publish()
            self.store.create_or_reconcile.assert_not_awaited()

    async def test_storage_refusal_or_changed_authority_never_succeeds(self):
        self.setup_case();self.authority.prepare_wrap_write.side_effect=ValueError('private detail')
        with self.assertRaisesRegex(WrapPublicationRejected,'^private wrap publication refused$'):await self.publish()
        self.store.create_or_reconcile.assert_not_awaited()
        self.setup_case();self.store.create_or_reconcile.return_value='different'
        with self.assertRaises(WrapPublicationRejected):await self.publish()
        self.setup_case();self.authority.prepare_wrap_write.side_effect=HistoryConflict('stale fence')
        with self.assertRaises(HistoryConflict):await self.publish()
        self.store.create_or_reconcile.assert_not_awaited()
        self.authority.commit_wrap_write.assert_not_awaited()
        self.setup_case();self.authority.commit_wrap_write.return_value=False
        with self.assertRaises(WrapPublicationRejected):await self.publish()

    async def test_expiry_during_storage_or_commit_refuses(self):
        self.setup_case()
        async def expired(*args):self.now=103;return DIGEST
        self.store.create_or_reconcile.side_effect=expired
        with self.assertRaises(WrapPublicationRejected):await self.publish()
        self.authority.commit_wrap_write.assert_not_awaited()
        self.setup_case()
        async def late_commit(*args):self.now=103;return True
        self.authority.commit_wrap_write.side_effect=late_commit
        with self.assertRaises(WrapPublicationRejected):await self.publish()

    async def test_cancellation_is_preserved_without_commit_or_retry(self):
        self.setup_case();self.store.create_or_reconcile.side_effect=asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):await self.publish()
        self.authority.commit_wrap_write.assert_not_awaited()
        self.store.create_or_reconcile.assert_awaited_once()
