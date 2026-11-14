"""Private allocation bindings do not enroll identities or bootstrap authority."""
import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from acl_service.infrastructure import media_allocation_bindings as module


def b64(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


@pytest.fixture
def configuration(tmp_path,monkeypatch):
    tenant=str(UUID(int=1));paths={}
    for name in ['history','freshness','storage','policy','source']:
        path=tmp_path/name;path.write_bytes(b'fixture');path.chmod(0o600);paths[name]=str(path)
    source=Ed25519PrivateKey.from_private_bytes(b'\x07'*32)
    issuer=Ed25519PrivateKey.from_private_bytes(b'\x08'*32)
    (tmp_path/'source').write_text(b64(source.private_bytes_raw()))
    (tmp_path/'policy').write_text(json.dumps({'jwks':{},'policy':{},'pinnedIss':[]}))
    row={'tenant':tenant,'subject':'subject','reader':'a'*43+'.'+'b'*43,
         'historyFile':paths['history'],'freshnessFile':paths['freshness'],'storageOrigin':'https://storage.example',
         'storageKeyFile':paths['storage'],'issuer':str(UUID(int=2)),'source':str(UUID(int=3)),
         'policyFile':paths['policy'],'policyUntil':2000,'keyId':'source','sourceKeyFile':paths['source'],
         'issuerKeys':{'storage':b64(issuer.public_key().public_bytes_raw())}}
    file=tmp_path/'config';file.chmod(0o600) if file.exists() else None
    def write(rows=None):
        file.write_text(json.dumps({'version':1,'bindings':[row] if rows is None else rows}));file.chmod(0o600)
        return {'SOCIACL_MEDIA_ALLOCATION_FILE':str(file)}
    provisioned=Mock();monkeypatch.setattr(module,'_provisioned',provisioned)
    source_factory=Mock(return_value=SimpleNamespace(production_ready=True,tenant=tenant))
    client_factory=Mock(return_value=SimpleNamespace(tenant=tenant))
    return SimpleNamespace(**locals())


def test_binding_uses_fixed_owner_and_current_native_source(configuration):
    c=configuration
    assert module.load_allocation_bindings({}) is None
    result=module.load_allocation_bindings(c.write(),source_factory=c.source_factory,client_factory=c.client_factory)
    value=result[(UUID(c.tenant),'subject')]
    assert value.reader==c.row['reader'] and value.issuer==c.row['issuer']
    c.provisioned.assert_called_once()
    assert c.provisioned.call_args.kwargs=={'allow_empty':True}
    c.source_factory.assert_called_once();c.client_factory.assert_called_once()


def test_conflicting_shared_files_keys_and_configuration_refuse(configuration):
    c=configuration
    bad=[{**c.row,'extra':True},{**c.row,'issuer':'bad'}, {**c.row,'storageKeyFile':str(c.file)},
         {**c.row,'issuerKeys':{'bad id':b64(c.issuer.public_key().public_bytes_raw())}}, {**c.row,'policyUntil':True},
         {**c.row,'sourceKeyFile':c.row['policyFile']},{**c.row,'issuerKeys':{}},
         {**c.row,'issuerKeys':{'storage':b64(c.source.public_key().public_bytes_raw())}}]
    for row in bad:
        with pytest.raises(ValueError,match='Invalid private'):
            module.load_allocation_bindings(c.write([row]),source_factory=c.source_factory,client_factory=c.client_factory)
    c.client_factory.assert_not_called()
    with pytest.raises(ValueError):
        module.load_allocation_bindings(c.write([c.row,{**c.row,'subject':'second','source':str(UUID(int=9))}]),
            source_factory=c.source_factory,client_factory=c.client_factory)
    c.source_factory.return_value.production_ready=False
    with pytest.raises(ValueError):
        module.load_allocation_bindings(c.write(),source_factory=c.source_factory,client_factory=c.client_factory)


def test_postgres_allocation_requires_the_same_source_identifier(configuration):
    c=configuration
    postgres_file=c.tmp_path/'postgres.json'
    postgres_file.write_text(json.dumps({'version':1,'databaseUrl':'postgresql+psycopg://runtime:private@db/acl',
        'historySchema':'acl_history','checkpointSchema':'acl_checkpoint','tenant':c.tenant,'source':c.row['source']}))
    postgres_file.chmod(0o600)
    row={key:value for key,value in c.row.items() if key not in ('historyFile','freshnessFile')}
    row['postgresFile']=str(postgres_file)
    def configured(row):
        c.file.write_text(json.dumps({'version':2,'bindings':[row]}));c.file.chmod(0o600)
        return {'SOCIACL_MEDIA_ALLOCATION_FILE':str(c.file)}
    values=module.load_allocation_bindings(configured(row),source_factory=c.source_factory,client_factory=c.client_factory)
    assert values[(UUID(c.tenant),'subject')].source==c.row['source']
    prepared=c.source_factory.call_args.args[0]
    assert prepared.history is None and prepared.postgres_settings.source==c.row['source']
    with pytest.raises(ValueError,match='Invalid private'):
        module.load_allocation_bindings(configured({**row,'source':str(UUID(int=99))}),
            source_factory=c.source_factory,client_factory=c.client_factory)
