"""Private group wrap settings units; authority and storage are mocked."""
import json
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID
import pytest
from acl_service.infrastructure import group_wrap_bindings as module
from test_group_allocation_bindings import configuration


def prepare(c,monkeypatch):
    row={k:c.row[k] for k in ('tenant','subject','reader','postgresFile','storageOrigin','storageKeyFile')}
    monkeypatch.setattr(module,'_provisioned',c.provisioned)
    monkeypatch.setattr(module,'_group_ready',Mock())
    def write(rows=None,version=2):
        c.file.write_text(json.dumps({'version':version,'bindings':rows or [row]}));c.file.chmod(0o600)
        return {'SOCIACL_GROUP_WRAP_FILE':str(c.file)}
    return row,write


def test_fixed_subject_and_shared_store(configuration,monkeypatch):
    c=configuration;row,write=prepare(c,monkeypatch)
    assert module.load_group_wrap_bindings({}) is None
    result=module.load_group_wrap_bindings(write([row,{**row,'subject':'second'}]),source_factory=c.source_factory,store_factory=c.client_factory)
    one=result[(UUID(c.tenant),'subject')];two=result[(UUID(c.tenant),'second')]
    assert one.reader==row['reader'] and one.store is two.store and one.authority is two.authority
    c.source_factory.assert_called_once();c.client_factory.assert_called_once()
    c.provisioned.assert_called_once()


def test_invalid_configuration_never_creates_storage_client(configuration,monkeypatch):
    c=configuration;row,write=prepare(c,monkeypatch)
    for bad in [{**row,'reader':'bad'},{**row,'extra':True},{**row,'storageOrigin':'http://unsafe'}]:
        with pytest.raises(ValueError,match='Invalid private group wrap'):
            module.load_group_wrap_bindings(write([bad]),source_factory=c.source_factory,store_factory=c.client_factory)
    for version in [1,3,True]:
        with pytest.raises(ValueError):module.load_group_wrap_bindings(write(version=version))
    c.source_factory.return_value.production_ready=False
    with pytest.raises(ValueError):module.load_group_wrap_bindings(write(),source_factory=c.source_factory,store_factory=c.client_factory)
    c.source_factory.return_value.production_ready=True
    (c.tmp_path/'storage').write_text('bad\nkey')
    with pytest.raises(ValueError):module.load_group_wrap_bindings(write(),source_factory=c.source_factory,store_factory=c.client_factory)
    c.client_factory.assert_not_called()


def test_allocation_source_must_match(configuration,monkeypatch):
    c=configuration;row,write=prepare(c,monkeypatch)
    authority=SimpleNamespace(tenant=c.tenant,production_ready=True,store=object())
    binding=SimpleNamespace(tenant=c.tenant,authority=authority,client=SimpleNamespace(origin=row['storageOrigin']))
    allocated={(UUID(c.tenant),'owner'):binding}
    same=Mock(return_value=True);monkeypatch.setattr(module,'_same_source',same)
    result=module.load_group_wrap_bindings(write(),allocation_bindings=allocated,store_factory=c.client_factory)
    assert result[(UUID(c.tenant),'subject')].authority is authority
    same.return_value=False
    with pytest.raises(ValueError):module.load_group_wrap_bindings(write(),allocation_bindings=allocated)
    same.return_value=True;binding.client.origin='https://different.example'
    with pytest.raises(ValueError):module.load_group_wrap_bindings(write(),allocation_bindings=allocated)
    other=SimpleNamespace(tenant=c.tenant,authority=object(),client=binding.client)
    with pytest.raises(ValueError):module.load_group_wrap_bindings(write(),allocation_bindings={1:binding,2:other})
