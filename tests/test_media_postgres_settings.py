"""Private PostgreSQL binding units with no database or network access."""
from contextlib import contextmanager
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from acl_service.infrastructure import media_bindings as bindings
from acl_service.infrastructure import media_postgres_settings as postgres

TENANT=str(UUID(int=1));SOURCE=str(UUID(int=2))


@pytest.fixture
def config(tmp_path):
    value={'version':1,'databaseUrl':'postgresql+psycopg://runtime:private@db/acl',
           'historySchema':'acl_s3rch_history','checkpointSchema':'acl_s3rch_checkpoint',
           'tenant':TENANT,'source':SOURCE}
    path=tmp_path/'postgres.json'
    def write(**changes):
        path.write_text(json.dumps({**value,**changes}));path.chmod(0o600)
        return path
    key=tmp_path/'storage';key.write_text('private');key.chmod(0o600)
    row={'tenant':TENANT,'subject':'fixed-subject','reader':'a'*43+'.'+'b'*43,
         'postgresFile':str(write()),'storageOrigin':'https://storage.example','storageKeyFile':str(key)}
    def binding():
        return bindings._prepared(bindings.parse_settings(json.dumps({'version':2,'bindings':[row]}).encode())[0])
    return SimpleNamespace(**locals())


def test_explicit_source_and_private_address(config, monkeypatch):
    c=config
    spec=postgres.read_postgres_settings(c.path,UUID(TENANT))
    assert 'private' not in repr(spec)
    factory=Mock();monkeypatch.setattr(postgres,'PostgresHistoryStore',factory)
    spec.open()
    factory.assert_called_once_with(c.value['databaseUrl'],history_schema='acl_s3rch_history',
        checkpoint_schema='acl_s3rch_checkpoint',tenant=TENANT,source=SOURCE,active_media_index=False)
    row=c.binding()
    assert row.history is None and row.freshness is None
    assert bindings._same_source(row,SimpleNamespace(binding_spec=spec))
    assert not bindings._same_source(row,SimpleNamespace(binding_spec=replace(spec,source=str(UUID(int=3)))))
    assert not bindings._same_source(row,SimpleNamespace())


@pytest.mark.parametrize('changes',[
    {'version':True},{'version':3},{'extra':True},{'tenant':str(UUID(int=3))},
    {'source':'bad'},{'source':str(UUID(int=0))},{'source':None},
    {'historySchema':'public'},{'checkpointSchema':'acl_s3rch_history'},
    {'databaseUrl':None},{'databaseUrl':'sqlite:///private'},
    {'databaseUrl':'postgresql+psycopg:///acl'}, {'databaseUrl':'postgresql+psycopg://user@db'},
])
def test_bad_private_spec_refuses(config,changes):
    with pytest.raises(ValueError):
        postgres.read_postgres_settings(config.write(**changes),UUID(TENANT))


def test_duplicate_and_oversized_private_configuration_refuses(config):
    for raw in ['{"version":1,"version":1}', ' '*8193]:
        config.path.write_text(raw)
        with pytest.raises(ValueError):
            postgres.read_postgres_settings(config.path,UUID(TENANT))


def test_prepared_source_is_snapshotted_once_per_tenant(config, monkeypatch):
    rows=[config.row,{**config.row,'subject':'second'}]
    parsed=bindings.parse_settings(json.dumps({'version':2,'bindings':rows}).encode())
    reader=Mock(return_value='private-spec');monkeypatch.setattr(postgres,'read_postgres_settings',reader)
    prepared=bindings._prepare_settings(parsed)
    assert prepared[0].postgres_settings==prepared[1].postgres_settings=='private-spec'
    reader.assert_called_once()


def test_provisioned_probe_is_read_only_and_always_closes(config, monkeypatch):
    binding=config.binding();store=Mock();db=Mock()
    @contextmanager
    def transaction(**options):
        assert options=={'write':False}
        yield db
    store._transaction=transaction
    monkeypatch.setattr(postgres.PostgresMediaSettings,'open',lambda _:store)
    for objects,checkpoint,allowed in [([],None,False),([],None,True),([('media_x',)],('digest',),False)]:
        db.execute.return_value.fetchall.return_value=objects
        db.execute.return_value.fetchone.return_value=checkpoint
        if not objects and not allowed:
            with pytest.raises(ValueError):bindings._provisioned(binding)
        else:
            bindings._provisioned(binding,allow_empty=allowed)
    assert store.close.call_count==3
    db.execute.return_value.fetchall.return_value=[('media_x',)]
    db.execute.return_value.fetchone.return_value=None
    with pytest.raises(ValueError):bindings._provisioned(binding)
    assert store.close.call_count==4
    with pytest.raises(ValueError):bindings._provisioned(replace(binding,postgres_settings=None))


def test_postgres_source_uses_fixed_bundle_and_closes_on_failure(config, monkeypatch):
    import sys
    binding=config.binding();store=Mock();factory=Mock(return_value=SimpleNamespace())
    modules={name:SimpleNamespace(__file__='/opt/acl-admission/'+name+'.py')
             for name in ('history_admission','statement_source','media_source','group_source','group_membership','group_key_source','group_wrap_source')}
    modules['media_source'].MediaSource=factory
    for name,value in modules.items():monkeypatch.setitem(sys.modules,name,value)
    monkeypatch.setattr(postgres.PostgresMediaSettings,'open',lambda _:store)
    assert bindings._source(binding) is factory.return_value
    assert store.binding_spec==binding.postgres_settings
    factory.assert_called_once_with(store,TENANT)
    factory.side_effect=ValueError('missing source')
    with pytest.raises(ValueError):bindings._source(binding)
    store.close.assert_called_once()


def test_delivery_reuses_only_identical_postgres_allocation(config, monkeypatch):
    import sys
    row=config.binding();store=SimpleNamespace(binding_spec=row.postgres_settings)
    authority=SimpleNamespace(production_ready=True,tenant=TENANT,store=store)
    allocation=SimpleNamespace(tenant=TENANT,authority=authority,client=SimpleNamespace(origin=row.origin))
    file=config.tmp_path/'bindings.json'
    file.write_text(json.dumps({'version':2,'bindings':[config.row]}));file.chmod(0o600)
    monkeypatch.setattr(bindings,'_provisioned',Mock())
    monkeypatch.setitem(sys.modules,'acl_service.interfaces.api.private_wrap_routes',SimpleNamespace(
        PrivateWrapBinding=lambda tenant,reader,authority,store:SimpleNamespace(authority=authority)))
    factory=Mock(side_effect=AssertionError('must reuse source'))
    result=bindings.load_media_bindings({bindings.CONFIG_NAME:str(file)},source_factory=factory,
        store_factory=Mock(),allocation_bindings={'owner':allocation})
    assert next(iter(result.values())).authority is authority
    store.binding_spec=replace(row.postgres_settings,source=str(UUID(int=3)))
    with pytest.raises(RuntimeError,match='Invalid private'):
        bindings.load_media_bindings({bindings.CONFIG_NAME:str(file)},source_factory=factory,
            store_factory=Mock(),allocation_bindings={'owner':allocation})


def test_v2_explicitly_selects_active_index_and_cannot_reuse_old_source(config, monkeypatch):
    old=postgres.read_postgres_settings(config.path,UUID(TENANT))
    current=postgres.read_postgres_settings(config.write(version=2),UUID(TENANT))
    assert current.active_media_index and not old.active_media_index
    factory=Mock();monkeypatch.setattr(postgres,'PostgresHistoryStore',factory)
    current.open()
    assert factory.call_args.kwargs['active_media_index'] is True
    assert not bindings._same_source(config.binding(),SimpleNamespace(binding_spec=old))


def test_active_startup_counts_only_active_entries_and_checks_primary(config,monkeypatch):
    from acl_service.domain.media_checkpoint import media_checkpoint_digest
    config.write(version=2);binding=config.binding();store=Mock();db=Mock()
    objects=[('media_one',)];row=(1,b'nonce',b'{}');missing=False;corrupt=False
    def execute(sql,args=()):
        result=Mock()
        if sql.startswith('SELECT object'):
            assert 'FROM freshness.media_active LIMIT 65' in sql
            result.fetchall.return_value=objects
        elif sql.startswith('SELECT digest'):
            result.fetchone.return_value=(b'wrong' if corrupt else media_checkpoint_digest(TENANT,'media_one',*row),)
        else:result.fetchone.return_value=None if missing else row
        return result
    db.execute.side_effect=execute
    @contextmanager
    def transaction(**options):yield db
    store._transaction=transaction
    monkeypatch.setattr(postgres.PostgresMediaSettings,'open',lambda _:store)
    bindings._provisioned(binding)
    missing=True
    with pytest.raises(ValueError,match='active checkpoint'):bindings._provisioned(binding)
    missing=False;corrupt=True
    with pytest.raises(ValueError,match='active checkpoint'):bindings._provisioned(binding)
    objects=[];bindings._provisioned(binding)
    objects=[('media_one',)]*65
    with pytest.raises(ValueError,match='not provisioned'):bindings._provisioned(binding)
