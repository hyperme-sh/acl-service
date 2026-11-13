"""HTTP client contract; executed only in CI with an in-process transport."""
import hashlib
from unittest import TestCase
import httpx
from acl_service.infrastructure.private_wrap_store import PrivateWrapStore, WrapStorageUnavailable

TENANT='12345678-1234-1234-1234-123456789abc'
NAME='a'*64
BODY=b'encrypted reader wrap'
REV=hashlib.sha256(BODY).hexdigest()


class PrivateWrapHTTPTests(TestCase):
    def test_private_tenant_headers_immutable_create_and_exact_read(self):
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
        with httpx.Client(transport=httpx.MockTransport(handler),trust_env=False,follow_redirects=False) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            self.assertEqual(store.create(NAME,BODY),REV)
            self.assertEqual(store.read(NAME,REV),BODY)
        self.assertEqual([r.method for r in requests],['PUT','GET'])

    def test_redirect_is_not_followed_and_provider_content_is_hidden(self):
        requests=[]
        def handler(request):
            requests.append(request)
            return httpx.Response(302,headers={'location':'https://other.example/private'},content=b'secret body')
        with httpx.Client(transport=httpx.MockTransport(handler),trust_env=False,follow_redirects=False) as client:
            store=PrivateWrapStore('https://storage.example',TENANT,'secret',client=client)
            with self.assertRaisesRegex(WrapStorageUnavailable,'^private wrap storage unavailable$'):
                store.read(NAME,REV)
        self.assertEqual(len(requests),1)
