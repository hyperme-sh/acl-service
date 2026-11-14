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
    def test_provisioned_files_require_tenant_and_every_checkpoint(self):
        binding=m.parse_settings(encode())[0]
        for tenant,objects,authority,checkpoint,okay in [
                ((TENANT,),[('object',)],('digest',),('digest',),True),
                (('other',),[('object',)],('digest',),('digest',),False),
                ((TENANT,),[],('digest',),('digest',),False),
                ((TENANT,),[('object',)]*65,('digest',),('digest',),False),
                ((TENANT,),[('object',)],None,('digest',),False),
                ((TENANT,),[('object',)],('digest',),None,False)]:
            history=Mock();history.execute.return_value.fetchone.return_value=tenant
            history.execute.return_value.fetchall.return_value=objects
            freshness=Mock();freshness.execute.return_value.fetchone.side_effect=[authority,checkpoint]
            with patch.object(m,'_private_file',side_effect=lambda _:io.BytesIO()),\
                    patch.object(m.os.path,'samefile',return_value=False),\
                    patch.object(m.sqlite3,'connect',side_effect=[history,freshness]):
                if okay:m._provisioned(binding)
                else:
                    with self.assertRaises(ValueError):m._provisioned(binding)
        with patch.object(m,'_private_file',side_effect=lambda _:io.BytesIO()),\
                patch.object(m.os.path,'samefile',return_value=True):
            with self.assertRaises(ValueError):m._provisioned(binding)

    def test_fixed_source_modules_and_checkpoint_requirement(self):
        binding=m.parse_settings(encode())[0]
        store=Mock();source=Mock()
        modules={name:SimpleNamespace(__file__='/opt/acl-admission/'+name+'.py')
                 for name in ('history_admission','statement_source','media_source')}
        modules['media_source'].MediaSource=source
        modules['acl_service.infrastructure.sqlite_history_store']=SimpleNamespace(SqliteHistoryStore=store)
        with patch.dict(sys.modules,modules):
            self.assertIs(m._source(binding),source.return_value)
        store.assert_called_once_with(binding.history,freshness_path=binding.freshness,require_authority_checkpoint=True)
        source.assert_called_once_with(store.return_value,TENANT)
        with patch.dict(sys.modules,{'history_admission':SimpleNamespace(__file__='/tmp/other.py')}):
            with self.assertRaises(ValueError):m._source(binding)

    def test_failed_fixed_module_import_does_not_poison_retry(self):
        binding=m.parse_settings(encode())[0]
        loader=SimpleNamespace(exec_module=Mock(side_effect=RuntimeError('broken module')))
        with patch.dict(sys.modules),patch.object(m.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=loader)),\
                patch.object(m.importlib.util,'module_from_spec',return_value=SimpleNamespace()):
            sys.modules.pop('history_admission',None)
            with self.assertRaises(RuntimeError):m._source(binding)
            self.assertNotIn('history_admission',sys.modules)

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

    def test_empty_delivery_requires_the_same_explicit_allocation_authority(self):
        expected=m.parse_settings(encode())[0]
        authority=SimpleNamespace(production_ready=True,tenant=TENANT,
            store=SimpleNamespace(path=expected.history,freshness_path=expected.freshness))
        allocation=SimpleNamespace(tenant=TENANT,authority=authority,client=SimpleNamespace(origin='https://storage.example'))
        factory=Mock(side_effect=AssertionError('must reuse allocation authority'))
        module=SimpleNamespace(PrivateWrapBinding=lambda tenant,reader,authority,store:
            SimpleNamespace(tenant=tenant,reader=reader,authority=authority,store=store))
        with patch.object(m,'_private_file',side_effect=[io.BytesIO(encode()),io.BytesIO(b'key')]),\
                patch.object(m,'_provisioned') as provisioned,patch.object(m.os.path,'samefile',return_value=True),\
                patch.dict(sys.modules,{'acl_service.interfaces.api.private_wrap_routes':module}):
            result=m.load_media_bindings({m.CONFIG_NAME:'/private/config'},source_factory=factory,store_factory=Mock(),
                allocation_bindings={'bound':allocation})
        self.assertIs(next(iter(result.values())).authority,authority)
        provisioned.assert_called_once_with(expected,allow_empty=True)
        factory.assert_not_called()
        with patch.object(m,'_private_file',return_value=io.BytesIO(encode())),\
                patch.object(m.os.path,'samefile',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'Invalid private media binding configuration'):
                m.load_media_bindings({m.CONFIG_NAME:'/private/config'},allocation_bindings={'bound':allocation})
