"""Explicit subject bindings and reloadable, expiring transfer eligibility."""
import copy
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import sys
from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.contact_bindings import parse_settings
from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique
from acl_service.domain.device_transfer import scope_value, principal_value


@dataclass(frozen=True)
class DeviceTransferBinding:
    principal: str
    source: object


def policy_reader(path):
    def read(at):
        with _private_file(path) as stream: raw = stream.read(65537)
        if len(raw) > 65536: raise AdmissionRejected('transfer policy capacity')
        p = json.loads(raw, object_pairs_hook=_unique)
        if (type(p) is not dict or set(p) != {'version','from','until','trust','scopes','activePrincipals'}
                or type(p['version']) is not int or p['version'] != 1
                or type(p['from']) is not int or type(p['until']) is not int
                or not 0 <= p['from'] <= at < p['until'] <= 9007199254740
                or type(p['trust']) is not dict or set(p['trust']) != {'jwks','policy','pinnedIss'}
                or type(p['scopes']) is not list or not 1 <= len(p['scopes']) <= 32
                or type(p['activePrincipals']) is not list or len(p['activePrincipals']) > 64):
            raise AdmissionRejected('transfer policy refused')
        for scope in p['scopes']: scope_value(scope)
        for principal in p['activePrincipals']: principal_value(principal)
        return copy.deepcopy(p)
    return read


def _source(settings, policy):
    for name in ('history_admission','statement_source','device_transfer_source'):
        path = Path('/opt/acl-admission') / (name + '.py')
        if name in sys.modules:
            if Path(sys.modules[name].__file__) != path: raise ValueError('unexpected verifier module')
            continue
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try: spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    store = settings.open()
    try: return sys.modules['device_transfer_source'].DeviceTransferSource(store, policy)
    except BaseException:
        store.close()
        raise


def load_device_transfer_bindings(environ=None, *, source_factory=None):
    configured = (os.environ if environ is None else environ).get('SOCIACL_DEVICE_TRANSFER_BINDINGS_FILE')
    if configured is None: return None
    sources, policies = {}, {}
    try:
        with _private_file(_path(configured)) as stream: rows = parse_settings(stream.read(65537))
        result = {}
        for row in rows:
            settings = read_postgres_settings(row.postgres_file, row.tenant)
            key = (settings.tenant, settings.source, settings.history_schema, settings.checkpoint_schema, settings.database_url)
            if key in policies and policies[key] != row.policy_file: raise ValueError('conflicting transfer policy')
            policies[key] = row.policy_file
            if key not in sources: sources[key] = (source_factory or _source)(settings, policy_reader(row.policy_file))
            result[(row.tenant, row.subject)] = DeviceTransferBinding(row.principal, sources[key])
        return result
    except Exception:
        for source in sources.values(): source.store.close()
        raise ValueError('Invalid transfer source configuration') from None
