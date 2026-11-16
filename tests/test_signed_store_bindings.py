"""Default-off signed store configuration with substituted storage."""
import json
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock,patch
from uuid import UUID
import pytest
from acl_service.infrastructure.signed_store_bindings import load_signed_store_bindings,policy_reader
from acl_service.domain.history_store import AdmissionRejected
P='acl_service.infrastructure.signed_store_bindings.'
T='12345678-1234-1234-1234-123456789abc';PRINCIPAL='a'*43+'.'+'b'*43

def test_disabled_shared_source_and_conflicting_policy_cleanup():
    assert load_signed_store_bindings({}) is None
    row=dict(tenant=T,subject='person',principal=PRINCIPAL,postgresFile='/private/postgres',policyFile='/private/policy')
    config=dict(version=1,bindings=[row]);settings=SimpleNamespace(tenant=T,source='source',history_schema='h',checkpoint_schema='c',database_url='private')
    source=SimpleNamespace(store=SimpleNamespace(close=Mock()));factory=Mock(return_value=source)
    with patch(P+'_private_file',side_effect=lambda _:BytesIO(json.dumps(config).encode())),patch(P+'read_postgres_settings',return_value=settings):
        result=load_signed_store_bindings({'SOCIACL_SIGNED_STORE_BINDINGS_FILE':'/private/bindings'},source_factory=factory)
        assert result[(UUID(T),'person')].principal==PRINCIPAL and result[(UUID(T),'person')].writer is source
        config['bindings'].append(dict(row,subject='other'))
        factory.reset_mock();assert len(load_signed_store_bindings({'SOCIACL_SIGNED_STORE_BINDINGS_FILE':'/private/bindings'},source_factory=factory))==2
        factory.assert_called_once()
        config['bindings'][1]['policyFile']='/private/other'
        with pytest.raises(ValueError):load_signed_store_bindings({'SOCIACL_SIGNED_STORE_BINDINGS_FILE':'/private/bindings'},source_factory=factory)
        source.store.close.assert_called_once()

def test_policy_reloads_and_rejects_expiry_extra_fields_or_invalid_principals():
    policy=dict(version=1,**{'from':90},until=110,trust=dict(jwks={},policy={},pinnedIss=[]),activePrincipals=[PRINCIPAL])
    with patch(P+'_private_file',side_effect=lambda _:BytesIO(json.dumps(policy).encode())):
        read=policy_reader('/private/policy');assert read(100)==policy
        policy['activePrincipals']=[];assert read(100)['activePrincipals']==[]
        for at in (89,110):
            with pytest.raises(AdmissionRejected):read(at)
        policy['extra']='untrusted'
        with pytest.raises(AdmissionRejected):read(100)
        del policy['extra'];policy['activePrincipals']=['invalid']
        with pytest.raises(ValueError):read(100)
    with patch(P+'_private_file',return_value=BytesIO(b'x'*65537)):
        with pytest.raises(AdmissionRejected):policy_reader('/private/policy')(100)
