"""Isolated units: fake client objects, no HTTP or storage execution."""
import hashlib
import sys
from unittest import TestCase
from unittest.mock import Mock, patch

from acl_service.infrastructure.private_wrap_store import (
    PrivateWrapStore, WrapStorageUnavailable, WrapStorageConflict, MAX_WRAP_BYTES,
)

TENANT = '12345678-1234-1234-1234-123456789abc'
NAME = 'a' * 64
PAYLOAD = b'opaque encrypted recipient material'
REV = hashlib.sha256(PAYLOAD).hexdigest()


class Response:
    def __init__(self, status=200, headers=None, chunks=None):
        self.status_code = status
        self.headers = headers if headers is not None else {'etag':'"'+REV+'"'}
        self.chunks = chunks if chunks is not None else [PAYLOAD]
        self.closed = False

    def __enter__(self): return self
    def __exit__(self, *_): self.closed = True
    def iter_raw(self, *, chunk_size):
        assert chunk_size == 4096
        yield from self.chunks


class PrivateWrapStoreTests(TestCase):
    def setUp(self):
        self.response = Response()
        self.client = Mock()
        self.client.stream.return_value = self.response
        self.store = PrivateWrapStore('https://storage.example',TENANT,'secret',client=self.client)

    def test_exact_revision_and_opaque_request_path(self):
        self.assertEqual(self.store.read(NAME,REV),PAYLOAD)
        args, kwargs = self.client.stream.call_args
        self.assertEqual(args,('GET','https://storage.example/api/v1/storage/records/media/'+NAME))
        self.assertEqual(kwargs['headers'],{'X-Api-Key':'secret','X-Tenant-ID':TENANT,'Accept-Encoding':'identity'})
        self.assertTrue(self.response.closed)
        self.store.close(); self.client.close.assert_called_once()

    def test_immutable_create_and_conflict_no_retry(self):
        self.client.stream.return_value = Response(201)
        self.assertEqual(self.store.create(NAME,PAYLOAD),REV)
        args, kwargs = self.client.stream.call_args
        self.assertEqual(args[0],'PUT')
        self.assertEqual(kwargs['content'],PAYLOAD)
        self.assertEqual(kwargs['headers']['If-None-Match'],'*')
        self.assertEqual(kwargs['headers']['Content-Length'],str(len(PAYLOAD)))
        self.client.reset_mock()
        self.client.stream.return_value = Response(412)
        with self.assertRaises(WrapStorageConflict): self.store.create(NAME,PAYLOAD)
        self.client.stream.assert_called_once()

    def test_bad_names_revisions_and_payloads_never_call_client(self):
        for value in ['', '../reader', 'owner/object', 'A'*64, None]:
            with self.assertRaises(ValueError): self.store.read(value,REV)
            with self.assertRaises(ValueError): self.store.create(value,PAYLOAD)
            with self.assertRaises(ValueError): self.store.read(NAME,value)
        for payload in [b'', bytearray(PAYLOAD), 'text', b'x'*(MAX_WRAP_BYTES+1)]:
            with self.assertRaises(ValueError): self.store.create(NAME,payload)
        self.client.stream.assert_not_called()

    def test_reader_refuses_provider_errors_mismatched_bytes_and_lengths(self):
        for response in [Response(404),Response(302),Response(headers={}),
            Response(headers={'etag':'"'+'b'*64+'"'}),
            Response(headers={'etag':'"'+REV+'"','content-encoding':'gzip'}),
            Response(headers={'etag':'"'+REV+'"','content-length':'0'}),
            Response(headers={'etag':'"'+REV+'"','content-length':'65537'}),
            Response(headers={'etag':'"'+REV+'"','content-length':'1'}),
            Response(chunks=[]),Response(chunks=[b'changed']),
            Response(chunks=[b'x'*MAX_WRAP_BYTES,b'x'])]:
            self.client.stream.return_value = response
            with self.assertRaisesRegex(WrapStorageUnavailable,'^private wrap storage unavailable$'):
                self.store.read(NAME,REV)
            self.assertTrue(response.closed)
        self.client.stream.return_value = Response(headers={'etag':'"'+REV+'"','content-length':str(len(PAYLOAD))})
        self.assertEqual(self.store.read(NAME,REV),PAYLOAD)

    def test_writer_refuses_bad_status_or_revision(self):
        for response in [Response(200),Response(302),Response(201,{})]:
            self.client.stream.return_value = response
            with self.assertRaises(WrapStorageUnavailable): self.store.create(NAME,PAYLOAD)
            self.assertTrue(response.closed)

    def test_cancellation_and_transport_failures_are_sanitized(self):
        def cancelled(): raise RuntimeError('secret provider body')
        for operation in [lambda:self.store.read(NAME,REV,cancel=cancelled),
                          lambda:self.store.create(NAME,PAYLOAD,cancel=cancelled)]:
            with self.assertRaisesRegex(WrapStorageUnavailable,'^private wrap storage unavailable$'): operation()
        self.client.stream.assert_not_called()
        self.client.stream.side_effect = RuntimeError('secret provider body')
        with self.assertRaises(WrapStorageUnavailable): self.store.read(NAME,REV)
        with self.assertRaises(WrapStorageUnavailable): self.store.create(NAME,PAYLOAD)

    def test_deadlines_before_request_after_headers_and_during_body(self):
        for times in [[0,2], [0,0,2], [0,0,0,2], [0,0,0,0,2]]:
            store = PrivateWrapStore('https://storage.example',TENANT,'secret',client=self.client,
                                     clock=Mock(side_effect=times))
            with self.assertRaises(WrapStorageUnavailable): store.read(NAME,REV)
        for times in [[0,2],[0,0,2]]:
            store = PrivateWrapStore('https://storage.example',TENANT,'secret',client=self.client,
                                     clock=Mock(side_effect=times))
            with self.assertRaises(WrapStorageUnavailable): store.create(NAME,PAYLOAD)

    def test_configuration_and_default_client_security(self):
        for origin in ['http://storage.example','https://u:p@storage.example','https://storage.example:444',
                       'https://storage.example/path','https://storage.example/?q=1','https://storage.example/#f',
                       'https:///']:
            with self.assertRaises(ValueError): PrivateWrapStore(origin,TENANT,'secret',client=self.client)
        for tenant in ['bad','00000000-0000-0000-0000-000000000000',TENANT.upper()]:
            with self.assertRaises(ValueError): PrivateWrapStore('https://storage.example',tenant,'secret',client=self.client)
        for key in ['', 'bad key', 'x'*4097, None]:
            with self.assertRaises(ValueError): PrivateWrapStore('https://storage.example',TENANT,key,client=self.client)
        module=Mock()
        with patch.dict(sys.modules,{'httpx':module}):
            PrivateWrapStore('https://storage.example/',TENANT,'secret')
        self.assertEqual(module.Client.call_args.kwargs['trust_env'],False)
        self.assertEqual(module.Client.call_args.kwargs['follow_redirects'],False)
