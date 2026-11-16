"""Credential configuration units with private file and storage substitutes."""
import json
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID
import pytest
from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.credential_bindings import load_credential_bindings, policy_reader

T='12345678-1234-1234-1234-123456789abc'
P='acl_service.infrastructure.credential_bindings.'

def test_policy_is_reloaded_and_expires():
    policy={'version':1,'from':90,'until':110,'trust':{'jwks':{},'policy':{},'pinnedIss':[]}}
    with patch(P+'_private_file',side_effect=lambda _:BytesIO(json.dumps(policy).encode())):
        read=policy_reader('/private/policy')
        assert read(100)==policy
        policy['trust']['pinnedIss']=['https://other.example']
        assert read(100)==policy
        for at in (89,110):
            with pytest.raises(AdmissionRejected):read(at)
        policy['principal']='caller subset'
        with pytest.raises(AdmissionRejected):read(100)
    with patch(P+'_private_file',return_value=BytesIO(b'x'*65537)):
        with pytest.raises(AdmissionRejected):policy_reader('/private/policy')(100)

def test_disabled_and_fixed_whole_source_binding():
    assert load_credential_bindings({}) is None
    row={'tenant':T,'subject':'issuer','postgresFile':'/private/postgres','policyFile':'/private/policy'}
    config={'version':1,'bindings':[row]}
    settings=SimpleNamespace(tenant=T,source='source',history_schema='history',checkpoint_schema='checkpoint',database_url='url')
    source=SimpleNamespace(store=SimpleNamespace(close=Mock()))
    factory=Mock(return_value=source)
    with patch(P+'_private_file',side_effect=lambda _:BytesIO(json.dumps(config).encode())),patch(P+'read_postgres_settings',return_value=settings):
        loaded=load_credential_bindings({'SOCIACL_CREDENTIAL_BINDINGS_FILE':'/private/bindings'},source_factory=factory)
        assert loaded[(UUID(T),'issuer')].source is source
        config['bindings'].append(dict(row,subject='other'))
        assert len(load_credential_bindings({'SOCIACL_CREDENTIAL_BINDINGS_FILE':'/private/bindings'},source_factory=factory))==2
        config['bindings'].append(dict(row))
        with pytest.raises(ValueError):load_credential_bindings({'SOCIACL_CREDENTIAL_BINDINGS_FILE':'/private/bindings'},source_factory=factory)
        source.store.close.assert_called_once()
        config['bindings']=[dict(row,principal='caller filter')]
        with pytest.raises(ValueError):load_credential_bindings({'SOCIACL_CREDENTIAL_BINDINGS_FILE':'/private/bindings'},source_factory=factory)
