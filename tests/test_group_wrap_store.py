from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock,AsyncMock
from test_private_wrap_store import Response,TENANT,REV,NAME,PAYLOAD

class GroupWrapStoreTests(IsolatedAsyncioTestCase):
    async def test_object_bound_routes_and_exact_digest_retry(self):
        import base64
        from acl_service.infrastructure.group_wrap_store import GroupWrapStore
        media='set_p_'+'ab'*64+'_'+'c'*32
        client=Mock(aclose=AsyncMock())
        root=GroupWrapStore('https://storage.example',TENANT,'secret',client=client)
        for bad in (None,'media_other',media+'/escape',media.upper()):
            with self.assertRaises(ValueError):root.for_group(bad)
        with self.assertRaises(ValueError):await root.read(REV,REV)
        bound=root.for_group(media)
        for status in (201,204):
            client.stream.return_value=Response(status)
            self.assertEqual(await bound.create_or_reconcile(REV,PAYLOAD),REV)
            args,kwargs=client.stream.call_args
            self.assertEqual(args,('PUT','https://storage.example/api/v1/storage/groups/wraps/'+media+'/'+REV))
            owner=base64.urlsafe_b64encode(bytes.fromhex('ab'*32)).rstrip(b'=').decode()
            self.assertEqual(kwargs['headers']['X-Group-Owner'],owner+'.'+owner)
            self.assertEqual(kwargs['headers']['X-Tenant-ID'],TENANT)
        client.stream.return_value=Response()
        self.assertEqual(await bound.read(REV,REV),PAYLOAD)
        calls=client.stream.call_count
        for operation in (bound.read(NAME,REV),bound.create(NAME,PAYLOAD),bound.create(REV,'bad')):
            with self.assertRaises(ValueError):await operation
        self.assertEqual(client.stream.call_count,calls)
        another=bound.for_group(media[:-1]+'d')
        self.assertNotEqual(another._path(REV),bound._path(REV))
        with self.assertRaises(ValueError):root._path(REV)
        await root.close();client.aclose.assert_awaited_once()
