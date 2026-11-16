"""Explicit service subjects bound to entire protected credential domains."""
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID
from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique


@dataclass(frozen=True)
class CredentialBinding:
    source: object


def policy_reader(path):
    def read(at):
        with _private_file(path) as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise AdmissionRejected('credential policy capacity')
        p = json.loads(raw, object_pairs_hook=_unique)
        if (type(p) is not dict or set(p) != {'version', 'from', 'until', 'trust'}
                or type(p['version']) is not int or p['version'] != 1
                or type(p['from']) is not int or type(p['until']) is not int
                or not 0 <= p['from'] <= at < p['until'] <= 9007199254740
                or type(p['trust']) is not dict or set(p['trust']) != {'jwks', 'policy', 'pinnedIss'}):
            raise AdmissionRejected('credential policy refused')
        return p
    return read


def _source(settings, policy):
    for name in ('history_admission', 'statement_source', 'credential_source'):
        path = Path('/opt/acl-admission') / (name + '.py')
        if name in sys.modules:
            if Path(sys.modules[name].__file__) != path:
                raise ValueError('unexpected verifier module')
            continue
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    store = settings.open()
    try:
        return sys.modules['credential_source'].CredentialSource(store, settings.tenant, settings.source, policy_at=policy)
    except BaseException:
        store.close()
        raise


def load_credential_bindings(environ=None, *, source_factory=None):
    configured = (os.environ if environ is None else environ).get('SOCIACL_CREDENTIAL_BINDINGS_FILE')
    if configured is None:
        return None
    sources, policies = {}, {}
    try:
        with _private_file(_path(configured)) as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('credential binding capacity')
        config = json.loads(raw, object_pairs_hook=_unique)
        if (type(config) is not dict or set(config) != {'version', 'bindings'}
                or type(config['version']) is not int or config['version'] != 1
                or type(config['bindings']) is not list or not 1 <= len(config['bindings']) <= 64):
            raise ValueError('invalid credential bindings')
        result = {}
        for row in config['bindings']:
            if type(row) is not dict or set(row) != {'tenant', 'subject', 'postgresFile', 'policyFile'}:
                raise ValueError('invalid credential binding')
            tenant = UUID(row['tenant'])
            if not tenant.int or str(tenant) != row['tenant']:
                raise ValueError('canonical tenant required')
            if type(row['subject']) is not str or not re.fullmatch(r'[\x21-\x7e]{1,256}', row['subject']):
                raise ValueError('invalid credential subject')
            binding_key = (tenant, row['subject'])
            if binding_key in result:
                raise ValueError('duplicate credential subject')
            settings = read_postgres_settings(_path(row['postgresFile']), tenant)
            policy_file = _path(row['policyFile'])
            key = (settings.tenant, settings.source, settings.history_schema, settings.checkpoint_schema, settings.database_url)
            if key in policies and policies[key] != policy_file:
                raise ValueError('conflicting credential policy')
            policies[key] = policy_file
            if key not in sources:
                sources[key] = (source_factory or _source)(settings, policy_reader(policy_file))
            result[binding_key] = CredentialBinding(sources[key])
        return result
    except Exception:
        for source in sources.values():
            source.store.close()
        raise ValueError('Invalid credential source configuration') from None
