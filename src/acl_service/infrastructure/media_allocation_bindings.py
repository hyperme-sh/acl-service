"""Explicit private allocation configuration, separate from existing object grants."""
import hashlib
import json
import os
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from acl_service.allocation_protocol.media_allocation_grant import _b64, _uuid, _integer
from acl_service.allocation_protocol.media_allocation_request import AllocationRequestSigner
from acl_service.domain.media_allocation import AllocationBinding, canonical
from acl_service.infrastructure.media_bindings import parse_settings, _provisioned, _source
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique
from acl_service.infrastructure.media_allocation_client import AllocationClient

BASE={'tenant','subject','reader','historyFile','freshnessFile','storageOrigin','storageKeyFile'}
EXTRA={'issuer','source','policyFile','policyUntil','keyId','sourceKeyFile','issuerKeys'}


def load_allocation_bindings(environ=None, *, source_factory=None, client_factory=None):
    configured=(os.environ if environ is None else environ).get('SOCIACL_MEDIA_ALLOCATION_FILE')
    if configured is None:return None
    clients={}
    try:
        with _private_file(_path(configured)) as stream:raw=stream.read(65537)
        if len(raw)>65536:raise ValueError()
        value=json.loads(raw,object_pairs_hook=_unique)
        if (type(value) is not dict or set(value)!={'version','bindings'} or type(value['version']) is not int
                or value['version']!=1 or type(value['bindings']) is not list or not 1<=len(value['bindings'])<=64):raise ValueError()
        if any(type(row) is not dict or set(row)!=BASE|EXTRA for row in value['bindings']):raise ValueError()
        settings=parse_settings(canonical({'version':1,'bindings':[{key:row[key] for key in BASE} for row in value['bindings']]}))
        prepared=[];tenants={};paths={}
        for binding,row in zip(settings,value['bindings']):
            _provisioned(binding,allow_empty=True)
            issuer,source=_uuid(row['issuer']),_uuid(row['source']);_integer(row['policyUntil'])
            policy_path,key_path=_path(row['policyFile']),_path(row['sourceKeyFile'])
            all_paths=(binding.history,binding.freshness,binding.key_file,policy_path,key_path)
            if len(set(all_paths))!=5 or any(os.path.samefile(a,b) for i,a in enumerate(all_paths) for b in all_paths[i+1:]):raise ValueError()
            if any(os.path.samefile(_path(configured),path) for path in all_paths):raise ValueError()
            for path in all_paths:
                if path in paths and paths[path]!=binding.tenant:raise ValueError()
                paths[path]=binding.tenant
            with _private_file(policy_path) as stream:policy_raw=stream.read(65537)
            if len(policy_raw)>65536:raise ValueError()
            policy=json.loads(policy_raw,object_pairs_hook=_unique)
            if type(policy) is not dict or set(policy)!={'jwks','policy','pinnedIss'}:raise ValueError()
            with _private_file(key_path) as stream:seed=stream.read(44).decode('ascii')
            signing_key=Ed25519PrivateKey.from_private_bytes(_b64(seed,32))
            if (type(row['issuerKeys']) is not dict or not 1<=len(row['issuerKeys'])<=16
                    or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',kid) for kid in row['issuerKeys'])):raise ValueError()
            keys={kid:Ed25519PublicKey.from_public_bytes(_b64(key,32)) for kid,key in row['issuerKeys'].items()}
            if any(key.public_bytes_raw()==signing_key.public_key().public_bytes_raw() for key in keys.values()):raise ValueError()
            signer=AllocationRequestSigner(issuer=issuer,source=source,tenant=str(binding.tenant),
                policy_digest=hashlib.sha256(canonical(policy)).hexdigest(),key_id=row['keyId'],signing_key=signing_key)
            spec=canonical({key:row[key] for key in EXTRA})
            if binding.tenant in tenants and tenants[binding.tenant]!=spec:raise ValueError()
            tenants[binding.tenant]=spec
            with _private_file(binding.key_file) as stream:credential=stream.read(4097).decode('ascii')
            prepared.append((binding,issuer,source,policy,signer,keys,credential,row['policyUntil']))
        sources={};result={}
        for binding,issuer,source,policy,signer,keys,credential,until in prepared:
            if binding.tenant not in sources:
                authority=(source_factory or _source)(binding)
                if not authority.production_ready or authority.tenant!=str(binding.tenant):raise ValueError()
                sources[binding.tenant]=authority
                clients[binding.tenant]=(client_factory or AllocationClient)(binding.origin,str(binding.tenant),credential)
            result[(binding.tenant,binding.subject)]=AllocationBinding(str(binding.tenant),binding.reader,sources[binding.tenant],
                clients[binding.tenant],signer,issuer,source,policy,until,keys)
        return result
    except Exception:
        raise ValueError('Invalid private media allocation configuration') from None
