"""HTTP client contract; executed only in CI with an in-process transport."""
import hashlib
import asyncio
from unittest import IsolatedAsyncioTestCase
import httpx
from acl_service.infrastructure.private_wrap_store import PrivateWrapStore, WrapStorageUnavailable

TENANT='12345678-1234-1234-1234-123456789abc'
NAME='a'*64
BODY=b'encrypted reader wrap'
REV=hashlib.sha256(BODY).hexdigest()


class PrivateWrapHTTPTests(IsolatedAsyncioTestCase):
    async def test_private_tenant_headers_immutable_create_and_exact_read(self):
        requests=[]
        def handler(request):
            requests.append(request)
            self.assertEqual(str(request.url),'https://storage.example/api/v1/storage/records/media/'+NAME)
            self.assertEqual(request.headers['x-tenant-id'],TENANT)
            self.assertEqual(request.headers['x-api-key'],'secret')
            self.assertEqual(request.headers['accept-encoding'],'identity')
            self.assertNotIn('cookie',request.headers)
            if request.method == 'PUT':
                self.assertEqual(request.headers['if-none-match'],'*')
                self.assertEqual(request.content,BODY)
                return httpx.Response(201,headers={'etag':'"'+REV+'"'})
            return httpx.Response(200,headers={'etag':'"'+REV+'"'},stream=httpx.ByteStream(BODY))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),trust_env=False,follow_redirects=True) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            self.assertEqual(await store.create(NAME,BODY),REV)
            self.assertEqual(await store.read(NAME,REV),BODY)
        self.assertEqual([r.method for r in requests],['PUT','GET'])

    async def test_redirect_is_not_followed_and_provider_content_is_hidden(self):
        requests=[]
        def handler(request):
            requests.append(request)
            return httpx.Response(302,headers={'location':'https://other.example/private'},content=b'secret body')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),trust_env=False,follow_redirects=True) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            with self.assertRaisesRegex(WrapStorageUnavailable,'^private wrap storage unavailable$'):
                await store.read(NAME,REV)
        self.assertEqual(len(requests),1)

    async def test_put_redirect_never_forwards_private_bytes(self):
        requests=[]
        def handler(request):
            requests.append(request)
            return httpx.Response(307,headers={'location':'https://other.example/private'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),follow_redirects=True) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            with self.assertRaises(WrapStorageUnavailable): await store.create(NAME,BODY)
        self.assertEqual(len(requests),1)

    async def test_total_deadline_interrupts_slow_headers(self):
        async def handler(request):
            await asyncio.sleep(10)
            return httpx.Response(200)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),timeout=None) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            with self.assertRaises(WrapStorageUnavailable):
                await asyncio.wait_for(store.read(NAME,REV),3)
            with self.assertRaises(WrapStorageUnavailable):
                await asyncio.wait_for(store.create(NAME,BODY),3)

    async def test_total_deadline_interrupts_buffered_trickle(self):
        class Trickle(httpx.AsyncByteStream):
            closed=False
            async def __aiter__(self):
                for _ in range(500):
                    await asyncio.sleep(0.05)
                    yield b'x'
            async def aclose(self): self.closed=True
        stream=Trickle()
        def handler(request):
            return httpx.Response(200,headers={'etag':'"'+REV+'"'},stream=stream)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),timeout=None) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            with self.assertRaises(WrapStorageUnavailable):
                await asyncio.wait_for(store.read(NAME,REV),3)
        self.assertTrue(stream.closed)
