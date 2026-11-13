"""Isolated authorization-fence units; no native verifier or storage execution."""
from dataclasses import replace
import hashlib
from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock, AsyncMock
from acl_service.domain.private_wrap_delivery import (
    WrapReadPermit, WrapDeliveryRejected, deliver_private_wrap, deliver_private_wrap_context,
)


class PrivateWrapDeliveryTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.payload=b'private wrap bytes'
        self.permit=WrapReadPermit('tenant','reader','object','a'*64,
            hashlib.sha256(self.payload).hexdigest(),1,'b'*64,'reader-epub','c'*64,110)
        self.authority=Mock(authorize_read=AsyncMock(),commit_delivery=AsyncMock())
        self.authority.authorize_read.return_value=self.permit
        self.authority.commit_delivery.return_value=True
        self.store=Mock(tenant='tenant',read=AsyncMock())
        self.store.read.return_value=self.payload

    async def run_delivery(self, **kwargs):
        return await deliver_private_wrap(self.authority,self.store,'tenant','reader','object',
                                    **{'clock':lambda:100,**kwargs})

    async def test_fetch_precedes_atomic_fence_commit(self):
        order=[]
        self.authority.authorize_read.side_effect=lambda *_:order.append('authorize') or self.permit
        self.store.read.side_effect=lambda *_args,**_kw:order.append('fetch') or self.payload
        self.authority.commit_delivery.side_effect=lambda permit:order.append('commit') or permit == self.permit
        self.assertEqual(await self.run_delivery(),self.payload)
        self.assertEqual(order,['authorize','fetch','commit'])
        self.authority.commit_delivery.assert_called_once_with(self.permit)

    async def test_context_is_from_the_exact_committed_permit(self):
        result = await deliver_private_wrap_context(self.authority, self.store, 'tenant',
                                                   'reader', 'object', clock=lambda:100)
        self.authority.commit_delivery.assert_called_once_with(self.permit)
        self.assertEqual(vars(result), {'payload': self.payload, 'object': 'object', 'epoch': 1,
            'revision_id': 'b'*64, 'reader_epub': 'reader-epub', 'expires_at': 110})

    async def test_wrong_binding_or_bad_context_never_fetches(self):
        for key,value in [('tenant','other'),('reader','other'),('object','other'),('record','../object'),
                          ('digest','bad'),('epoch',True),('revision_id','bad'),('fence','bad'),
                          ('expires_at',100),('reader_epub','')]:
            self.authority.authorize_read.return_value=replace(self.permit,**{key:value})
            with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()
        self.authority.authorize_read.return_value=None
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()
        self.store.read.assert_not_called()

    async def test_cross_tenant_store_does_not_call_authority(self):
        self.store.tenant='other'
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()
        self.authority.authorize_read.assert_not_called()

    async def test_authority_change_during_fetch_refuses(self):
        def fetch(*_args,**_kw):
            self.authority.commit_delivery.return_value=False
            return self.payload
        self.store.read.side_effect=fetch
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()
        self.authority.commit_delivery.return_value=1
        self.store.read.side_effect=None
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()

    async def test_corrupt_or_expired_payload_is_not_committed(self):
        for value in [b'wrong',b'',bytearray(self.payload),b'x'*65537]:
            self.store.read.return_value=value
            with self.assertRaises(WrapDeliveryRejected):await self.run_delivery()
        self.store.read.return_value=self.payload
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery(clock=Mock(side_effect=[100,110]))
        self.authority.commit_delivery.assert_not_called()

    async def test_errors_expiry_and_cancellation_after_commit_return_no_bytes(self):
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery(clock=Mock(side_effect=[100,100,110]))
        self.authority.commit_delivery.side_effect=RuntimeError('private diagnostics')
        with self.assertRaisesRegex(WrapDeliveryRejected,'^private wrap delivery refused$'):await self.run_delivery()
        with self.assertRaises(WrapDeliveryRejected):await self.run_delivery(cancel=Mock(side_effect=RuntimeError('cancelled')))
