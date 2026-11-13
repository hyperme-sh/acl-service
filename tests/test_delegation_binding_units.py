"""Isolated binding selection units; no storage, HTTP or cryptographic calls."""
from types import SimpleNamespace
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, Mock
from uuid import UUID
import sys
from acl_service.infrastructure.delegation_bindings import CONFIG_NAME, load_delegation_bindings
from acl_service.infrastructure.statement_bindings import BindingSettings, _source


class DelegationBindingUnits(TestCase):
    def test_disabled_never_uses_statement_settings(self):
        self.assertIsNone(load_delegation_bindings({'SOCIACL_STATEMENT_BINDINGS_FILE':'/private/statements'}))

    def test_configured_path_and_factory_are_explicit(self):
        factory = Mock()
        with patch('acl_service.infrastructure.delegation_bindings.load_statement_bindings', return_value={}) as load:
            self.assertEqual(load_delegation_bindings({CONFIG_NAME:'/private/agents'},source_factory=factory),{})
            load.assert_called_once_with({'SOCIACL_STATEMENT_BINDINGS_FILE':'/private/agents'},source_factory=factory)

    def test_errors_redact_configuration(self):
        with patch('acl_service.infrastructure.delegation_bindings.load_statement_bindings',side_effect=ValueError('private-path')):
            with self.assertRaisesRegex(RuntimeError,'^Invalid delegation source binding configuration$'):
                load_delegation_bindings({CONFIG_NAME:'/private/agents'})

    def test_default_factory_only_loads_image_owned_delegation_source(self):
        binding = BindingSettings(UUID('a5ed86d0-cb50-4404-a5ac-410aab086a82'),'service','agents',Path('/history'),Path('/freshness'))
        factory, store = Mock(), Mock()
        modules = {name:SimpleNamespace(__file__='/opt/acl-admission/'+name+'.py')
                   for name in ('history_admission','statement_source','delegation_source')}
        modules['delegation_source'].DelegationSource=factory
        modules['acl_service.infrastructure.sqlite_history_store']=SimpleNamespace(SqliteHistoryStore=store)
        def load(env, *, source_factory):
            return source_factory(binding)
        with patch.dict(sys.modules,modules), patch('acl_service.infrastructure.delegation_bindings.load_statement_bindings',side_effect=load):
            self.assertIs(load_delegation_bindings({CONFIG_NAME:'/private/agents'}),factory.return_value)
        store.assert_called_once_with(binding.history,freshness_path=binding.freshness,require_authority_checkpoint=True)
        factory.assert_called_once_with(store.return_value,str(binding.tenant))
        modules['delegation_source'].__file__='/tmp/foreign.py'
        with patch.dict(sys.modules,modules), self.assertRaisesRegex(ValueError,'unexpected verifier module'):
            _source(binding,delegations=True)
