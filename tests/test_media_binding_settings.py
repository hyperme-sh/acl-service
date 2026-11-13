"""Isolated binding configuration units; no database or transport execution."""
import io
import json
import sys
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from acl_service.infrastructure import media_bindings as m

TENANT = '01234567-89ab-cdef-0123-456789abcdef'
READER = 'a'*43 + '.' + 'b'*43


def row(**changes):
    value = dict(tenant=TENANT, subject='reader-subject', reader=READER,
                 historyFile='/private/history', freshnessFile='/private/freshness',
                 storageOrigin='https://storage.example', storageKeyFile='/private/key')
    value.update(changes)
    return value


def encode(rows=None):
    return json.dumps({'version':1,'bindings':rows if rows is not None else [row()]}).encode()


class MediaBindingUnits(TestCase):
    def test_fixed_reader_mapping_reuses_source_and_client(self):
        source=Mock(return_value=SimpleNamespace(production_ready=True,tenant=TENANT))
        client=Mock(return_value=object())
        module=SimpleNamespace(PrivateWrapBinding=lambda tenant,reader,authority,store:
            SimpleNamespace(tenant=tenant,reader=reader,authority=authority,store=store))
        with patch.object(m,'_private_file',side_effect=[io.BytesIO(encode([row(),row(subject='second')])),io.BytesIO(b'key')]),\
                patch.object(m,'_provisioned'),\
                patch.dict(sys.modules,{'acl_service.interfaces.api.private_wrap_routes':module}):
            result=m.load_media_bindings({m.CONFIG_NAME:'/private/config'},source_factory=source,store_factory=client)
        values=list(result.values())
        self.assertEqual(len(values),2)
        self.assertEqual(values[0].reader,READER)
        self.assertIs(values[0].authority,values[1].authority)
        self.assertIs(values[0].store,values[1].store)
        source.assert_called_once()
        client.assert_called_once_with('https://storage.example',TENANT,'key')

    def test_explicit_subject_reader_and_shared_tenant(self):
        rows=m.parse_settings(encode([row(),row(subject='second',reader='c'*43+'.'+'d'*43)]))
        self.assertEqual(rows[0].reader,READER)
        self.assertEqual(rows[0].history,rows[1].history)
        self.assertEqual(str(rows[0].tenant),TENANT)
        self.assertIsNone(m.load_media_bindings({}))

    def test_invalid_envelopes(self):
        for value in [b'[]',b'null',b'{}',b'{',b'\xff',b' '*65537,
                      b'{"version":1,"version":1,"bindings":[]}',encode([]),encode([row()]*65),
                      b'{"version":true,"bindings":[]}']:
            with self.subTest(value=value[:80]),self.assertRaises((ValueError,UnicodeError)):
                m.parse_settings(value)

    def test_bad_fields_and_conflicting_tenant_stores(self):
        cases={'tenant':[None,TENANT.upper(),'00000000-0000-0000-0000-000000000000'],
               'subject':[None,'','a b','x'*257], 'reader':[None,'wallet','a'*87],
               'storageOrigin':[None,'http://storage.example','https://x/','https://x:443',
                                'https://user@x','https://x?q=1','https://x#fragment'],
               'historyFile':['relative','/a/../b','/private/freshness','/private/key'],
               'storageKeyFile':['/private/freshness']}
        for field,values in cases.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    m.parse_settings(encode([row(**{field:value})]))
        for rows in [[row(),row()], [row(),row(subject='other',historyFile='/different')],
                     [row(),row(tenant='11234567-89ab-cdef-0123-456789abcdef')],
                     [dict(row(),extra=True)], [None]]:
            with self.assertRaises(ValueError):m.parse_settings(encode(rows))

    def test_all_validation_precedes_source_construction_and_errors_are_private(self):
        source=Mock()
        with patch.object(m,'_private_file',return_value=io.BytesIO(encode())),\
                patch.object(m,'_provisioned',side_effect=ValueError('private path and subject')):
            with self.assertRaisesRegex(RuntimeError,'^Invalid private media binding configuration$'):
                m.load_media_bindings({m.CONFIG_NAME:'/private/config'},source_factory=source)
        source.assert_not_called()

    def test_unprotected_source_refuses_before_client_creation(self):
        for source in [SimpleNamespace(production_ready=False,tenant=TENANT),
                       SimpleNamespace(production_ready=True,tenant='other')]:
            client=Mock()
            with patch.object(m,'_private_file',side_effect=[io.BytesIO(encode()),io.BytesIO(b'key')]),\
                    patch.object(m,'_provisioned'):
                with self.assertRaises(RuntimeError):m.load_media_bindings(
                    {m.CONFIG_NAME:'/private/config'},source_factory=lambda _:source,store_factory=client)
            client.assert_not_called()

    def test_secret_is_bounded_and_never_whitespace_normalized(self):
        for key in [b'',b'key\n',b'x'*4097,b'\xff']:
            source=Mock()
            with patch.object(m,'_private_file',side_effect=[io.BytesIO(encode()),io.BytesIO(key)]),\
                    patch.object(m,'_provisioned'):
                with self.assertRaises(RuntimeError):m.load_media_bindings(
                    {m.CONFIG_NAME:'/private/config'},source_factory=source)
            source.assert_not_called()
