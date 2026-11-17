"""Private configuration and cleanup units; no source or policy is provisioned."""
import copy
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import acl_service.infrastructure.rotation_witness_bindings as bindings

TENANT='12345678-1234-1234-1234-123456789abc'
ROW=dict(tenant=TENANT,subject='owner',principal='a'*43+'.'+'b'*43,postgresFile='/source',policyFile='/policy',kid='key',signingKeyFile='/key')


@pytest.fixture
def configured(monkeypatch):
    doc={'version':1,'bindings':[copy.deepcopy(ROW)]}
    pem=ec.derive_private_key(5,ec.SECP256R1()).private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
    files={'/key':pem}
    monkeypatch.setattr(bindings,'_private_file',lambda path:BytesIO(json.dumps(doc).encode() if str(path)=='/config' else files[str(path)]))
    settings=SimpleNamespace(tenant=UUID(TENANT),source='source',history_schema='history',checkpoint_schema='checkpoint',database_url='private-url')
    monkeypatch.setattr(bindings,'read_postgres_settings',lambda *_:settings)
    source=SimpleNamespace(store=Mock())
    factory=Mock(return_value=source)
    def load():return bindings.load_rotation_bindings('protected-policy',{'SOCIACL_ROTATION_BINDINGS_FILE':'/config'},source_factory=factory)
    return doc,files,source,factory,load


def test_default_off_and_shared_bound_source(configured):
    doc,files,source,factory,load=configured
    assert bindings.load_rotation_bindings(None,{}) is None
    doc['bindings'].append({**ROW,'subject':'second'})
    result=load()
    assert result[(UUID(TENANT),'owner')].source is source
    assert result[(UUID(TENANT),'second')].source is source
    factory.assert_called_once()
    assert factory.call_args.args[2:4]==('protected-policy','key')
    assert isinstance(factory.call_args.args[4].curve,ec.SECP256R1)


@pytest.mark.parametrize('change',[lambda d:d.update(version=True),lambda d:d.update(extra=1),lambda d:d.update(bindings=[]),
    lambda d:d['bindings'][0].update(kid=''),lambda d:d['bindings'][0].update(kid='x\n'),
    lambda d:d['bindings'][0].update(signingKeyFile='relative'),lambda d:d['bindings'][0].update(secret='x'),
    lambda d:d['bindings'].append(copy.deepcopy(ROW))])
def test_invalid_configuration_is_sanitized(configured,change):
    doc,files,source,factory,load=configured;change(doc)
    with pytest.raises(ValueError,match='^Invalid rotation signing configuration$'):load()
    factory.assert_not_called()


def test_conflicting_signer_closes_opened_source(configured):
    doc,files,source,factory,load=configured
    doc['bindings'].append({**ROW,'subject':'second','kid':'different'})
    with pytest.raises(ValueError):load()
    source.store.close.assert_called_once()


@pytest.mark.parametrize('key',[b'bad',b'x'*8193,ec.derive_private_key(5,ec.SECP384R1()).private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())])
def test_private_key_shape_refuses_before_source_open(configured,key):
    doc,files,source,factory,load=configured;files['/key']=key
    with pytest.raises(ValueError):load()
    factory.assert_not_called()


def test_source_import_and_constructor_cleanup(monkeypatch):
    from contextlib import ExitStack
    from unittest.mock import patch
    store=Mock();settings=SimpleNamespace(open=lambda:store)
    module=SimpleNamespace(__file__='/opt/acl-admission/rotation_witness_source.py',RotationWitnessSource=Mock(return_value='source'))
    with ExitStack() as stack:
        for name in ('history_admission','statement_source','rotation_publish_source','rotation_witness_source'):
            value=module if name=='rotation_witness_source' else SimpleNamespace(__file__='/opt/acl-admission/'+name+'.py')
            stack.enter_context(patch.dict(bindings.sys.modules,{name:value}))
        assert bindings._source(settings,'policy','witness','kid','private')=='source'
        module.RotationWitnessSource.side_effect=ValueError('private error')
        with pytest.raises(ValueError):bindings._source(settings,'policy','witness','kid','private')
        store.close.assert_called_once()
        module.__file__='/unexpected'
        with pytest.raises(ValueError):bindings._source(settings,'policy','witness','kid','private')


@pytest.mark.parametrize('failure',[False,True])
def test_private_module_loader_rolls_back_failed_import(monkeypatch,failure):
    for name in ('history_admission','statement_source','rotation_publish_source','rotation_witness_source'):
        # Track absence too, so modules inserted by the loader cannot escape this test.
        monkeypatch.setitem(bindings.sys.modules,name,None)
        del bindings.sys.modules[name]
    def execute(module):
        if failure:raise ImportError('unavailable')
    monkeypatch.setattr(bindings.importlib.util,'spec_from_file_location',lambda name,path:SimpleNamespace(origin=str(path),loader=SimpleNamespace(exec_module=execute)))
    monkeypatch.setattr(bindings.importlib.util,'module_from_spec',lambda spec:SimpleNamespace(__file__=spec.origin,RotationWitnessSource=lambda *a,**k:'source'))
    store=Mock();settings=SimpleNamespace(open=lambda:store)
    if failure:
        with pytest.raises(ImportError):bindings._source(settings,None,None,None,None)
        assert 'history_admission' not in bindings.sys.modules
        store.close.assert_not_called()
    else:assert bindings._source(settings,None,None,None,None)=='source'


@pytest.mark.asyncio
@pytest.mark.parametrize('failure',[False,True])
async def test_startup_owns_sources_and_cleans_up_on_configuration_refusal(monkeypatch,failure):
    from unittest.mock import AsyncMock
    import acl_service.app as app_module
    import acl_service.infrastructure.witness_policy_repo as policy_repo
    async_engine=SimpleNamespace(dispose=AsyncMock())
    sync_engine=Mock()
    consumer=SimpleNamespace(start=AsyncMock(),stop=AsyncMock())
    monkeypatch.setattr(app_module,'create_async_engine',lambda *_:async_engine)
    monkeypatch.setattr(app_module,'create_engine',lambda *a,**k:sync_engine)
    monkeypatch.setattr(app_module,'async_sessionmaker',Mock())
    monkeypatch.setattr(app_module,'configure_session_maker',Mock())
    monkeypatch.setattr(app_module,'configure_logging',Mock())
    monkeypatch.setattr(app_module,'load_publication',lambda:None)
    monkeypatch.setattr(app_module,'build_user_created_consumer',lambda *_:consumer)
    for name in ('PostgresContactLaneStore','PostgresFirstContactStore','PostgresPolicyStore','PostgresRecoveryStore','PostgresMembershipReader','PostgresShareStore','PostgresWitnessPolicyReader'):
        monkeypatch.setattr(app_module,name,Mock())
    policy=object();monkeypatch.setattr(policy_repo,'PostgresWitnessSigningPolicyReader',lambda engine:policy)
    source=SimpleNamespace(store=Mock())
    value={(UUID(TENANT),'owner'):bindings.RotationBinding(ROW['principal'],source)}
    loader=Mock(return_value=value,side_effect=ValueError('invalid') if failure else None)
    monkeypatch.setattr(bindings,'load_rotation_bindings',loader)
    app=app_module.create_app(signed_store_bindings={},credential_bindings={},device_transfer_bindings={},contact_bindings={},statement_bindings={},delegation_bindings={},media_allocation_bindings={},group_allocation_bindings={},group_wrap_bindings={},private_wrap_bindings={})
    if failure:
        with pytest.raises(ValueError):
            async with app.router.lifespan_context(app):raise AssertionError('startup must refuse')
        source.store.close.assert_not_called()
    else:
        async with app.router.lifespan_context(app):
            assert app.state.rotation_witness_bindings[(UUID(TENANT),'owner')].source is source
        source.store.close.assert_called_once()
        assert app.state.rotation_witness_bindings is None
    loader.assert_called_once_with(policy)
    consumer.stop.assert_awaited_once();sync_engine.dispose.assert_called_once();async_engine.dispose.assert_awaited_once()


def test_publication_flag_is_explicit_and_default_off():
    assert bindings.load_rotation_publication_enabled({}) is False
    assert bindings.load_rotation_publication_enabled({'SOCIACL_ROTATION_PUBLICATION_ENABLED':'0'}) is False
    assert bindings.load_rotation_publication_enabled({'SOCIACL_ROTATION_PUBLICATION_ENABLED':'1'}) is True
    with pytest.raises(ValueError):bindings.load_rotation_publication_enabled({'SOCIACL_ROTATION_PUBLICATION_ENABLED':'true'})
