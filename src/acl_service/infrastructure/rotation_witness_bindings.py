"""Private startup bindings for the existing protected wallet-rotation source."""
import importlib.util
import json
import os
from pathlib import Path
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from acl_service.infrastructure.contact_bindings import parse_settings
from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
from acl_service.infrastructure.signed_store_bindings import policy_reader
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique
from acl_service.interfaces.api.rotation_witness_routes import RotationBinding


def _source(settings, policy, witness_policy, kid, private_key):
    for name in ('history_admission','statement_source','rotation_publish_source','rotation_witness_source'):
        path=Path('/opt/acl-admission')/(name+'.py')
        if name in sys.modules:
            if Path(sys.modules[name].__file__)!=path:raise ValueError('unexpected verifier module')
            continue
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        try:spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name,None)
            raise
    store=settings.open()
    try:
        return sys.modules['rotation_witness_source'].RotationWitnessSource(store,policy_at=policy,
            witness_policy=witness_policy,kid=kid,private_key=private_key)
    except BaseException:
        store.close()
        raise


def load_rotation_bindings(witness_policy, environ=None, *, source_factory=None):
    configured=(os.environ if environ is None else environ).get('SOCIACL_ROTATION_BINDINGS_FILE')
    if configured is None:return None
    sources={}
    try:
        with _private_file(_path(configured)) as stream:raw=stream.read(65537)
        if len(raw)>65536:raise ValueError('configuration capacity')
        doc=json.loads(raw,object_pairs_hook=_unique)
        if type(doc) is not dict or set(doc)!={'version','bindings'} or type(doc['bindings']) is not list:raise ValueError('configuration shape')
        base,signers=[],[]
        for row in doc['bindings']:
            fields={'tenant','subject','principal','postgresFile','policyFile','kid','signingKeyFile'}
            if type(row) is not dict or set(row)!=fields:raise ValueError('binding shape')
            kid=row['kid']
            if type(kid) is not str or not 1<=len(kid)<=128 or not kid.isascii() or not all(33<=ord(c)<=126 for c in kid):raise ValueError('signing key id')
            signers.append((kid,_path(row['signingKeyFile'])))
            base.append({key:row[key] for key in fields-{'kid','signingKeyFile'}})
        rows=parse_settings(json.dumps({'version':doc['version'],'bindings':base}).encode())
        result,policies={},{}
        for row,(kid,key_path) in zip(rows,signers,strict=True):
            settings=read_postgres_settings(row.postgres_file,row.tenant)
            key=(settings.tenant,settings.source,settings.history_schema,settings.checkpoint_schema,settings.database_url)
            selection=(row.policy_file,kid,key_path)
            if key in policies and policies[key]!=selection:raise ValueError('conflicting rotation authority')
            policies[key]=selection
            if key not in sources:
                with _private_file(key_path) as stream:pem=stream.read(8193)
                if len(pem)>8192:raise ValueError('key capacity')
                private_key=load_pem_private_key(pem,password=None)
                if not isinstance(private_key,ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve,ec.SECP256R1):raise ValueError('key curve')
                sources[key]=(source_factory or _source)(settings,policy_reader(row.policy_file),witness_policy,kid,private_key)
            result[(row.tenant,row.subject)]=RotationBinding(row.principal,sources[key])
        return result
    except Exception:
        for source in sources.values():source.store.close()
        raise ValueError('Invalid rotation signing configuration') from None


def load_rotation_publication_enabled(environ=None):
    value=(os.environ if environ is None else environ).get('SOCIACL_ROTATION_PUBLICATION_ENABLED','0')
    if value not in ('0','1'):raise ValueError('invalid rotation publication setting')
    return value == '1'
