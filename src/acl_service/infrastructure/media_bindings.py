"""Explicit subject-to-reader bindings for already provisioned private media."""
from contextlib import closing
from dataclasses import dataclass, replace
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from urllib.parse import urlsplit
from uuid import UUID

from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique

CONFIG_NAME = 'SOCIACL_MEDIA_BINDINGS_FILE'
MAX_CONFIG_BYTES = 65536


@dataclass(frozen=True)
class MediaSettings:
    tenant: UUID
    subject: str
    reader: str
    history: Path | None
    freshness: Path | None
    origin: str
    key_file: Path
    postgres_file: Path | None = None
    postgres_settings: object | None = None


def parse_settings(raw):
    if type(raw) is not bytes or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('invalid media configuration')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) != {'version', 'bindings'}
            or type(value['version']) is not int or value['version'] not in (1, 2)
            or type(value['bindings']) is not list or not 1 <= len(value['bindings']) <= 64):
        raise ValueError('invalid media configuration')
    result, keys, tenants, paths = [], set(), {}, {}
    base={'tenant','subject','reader','storageOrigin','storageKeyFile'}
    fields=base|({'historyFile','freshnessFile'} if value['version']==1 else {'postgresFile'})
    for row in value['bindings']:
        if type(row) is not dict or set(row) != fields:
            raise ValueError('invalid media binding')
        if type(row['tenant']) is not str:
            raise ValueError('invalid tenant')
        tenant = UUID(row['tenant'])
        if not tenant.int or str(tenant) != row['tenant']:
            raise ValueError('invalid tenant')
        subject, reader = row['subject'], row['reader']
        if (type(subject) is not str or re.fullmatch(r'[\x21-\x7e]{1,256}', subject) is None
                or type(reader) is not str or re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}', reader) is None):
            raise ValueError('invalid subject or reader')
        origin = row['storageOrigin']
        if type(origin) is not str:
            raise ValueError('invalid storage origin')
        parsed = urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.port or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('invalid storage origin')
        history=freshness=postgres_file=None
        key_file=_path(row['storageKeyFile'])
        if value['version']==1:
            history,freshness=(_path(row[k]) for k in ('historyFile','freshnessFile'))
        else:
            postgres_file=_path(row['postgresFile'])
        private_paths=tuple(p for p in (history,freshness,postgres_file,key_file) if p is not None)
        if len(set(private_paths)) != len(private_paths) or (tenant, subject) in keys:
            raise ValueError('duplicate media binding or file')
        # One worker and storage client per tenant, shared by every bound reader.
        spec = (history, freshness, postgres_file, origin, key_file)
        if tenant in tenants and tenants[tenant] != spec:
            raise ValueError('conflicting tenant storage')
        for path in private_paths:
            if path in paths and paths[path] != (tenant, spec):
                raise ValueError('conflicting file ownership')
            paths[path] = (tenant, spec)
        tenants[tenant] = spec
        keys.add((tenant, subject))
        result.append(MediaSettings(tenant, subject, reader, history, freshness, origin, key_file, postgres_file))
    return tuple(result)


def _prepared(binding):
    if binding.postgres_file is None:
        return binding
    from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
    return replace(binding, postgres_settings=read_postgres_settings(binding.postgres_file,binding.tenant))


def _prepare_settings(settings):
    prepared={}
    result=[]
    for row in settings:
        if row.postgres_file is not None:
            if row.tenant not in prepared:
                prepared[row.tenant]=_prepared(row).postgres_settings
            row=replace(row,postgres_settings=prepared[row.tenant])
        result.append(row)
    return tuple(result)


def _same_source(binding, store):
    if binding.postgres_file is not None:
        return binding.postgres_settings is not None and getattr(store,'binding_spec',None)==binding.postgres_settings
    return (os.path.samefile(binding.history,store.path)
            and os.path.samefile(binding.freshness,store.freshness_path))


def _provisioned(binding, *, allow_empty=False):
    if binding.postgres_file is not None:
        if binding.postgres_settings is None:
            raise ValueError('unprepared PostgreSQL configuration')
        with _private_file(binding.key_file):
            pass
        if os.path.samefile(binding.postgres_file,binding.key_file):
            raise ValueError('independent private files required')
        with closing(binding.postgres_settings.open()) as store:
            with store._transaction(write=False) as db:
                objects=db.execute('SELECT object FROM media_sources LIMIT 65').fetchall()
                if not (0 if allow_empty else 1)<=len(objects)<=64:
                    raise ValueError('media sources not provisioned')
                if any(not db.execute('SELECT digest FROM freshness.media_checkpoints WHERE object=?',tuple(row)).fetchone() for row in objects):
                    raise ValueError('media checkpoint not provisioned')
        return
    for path in (binding.history, binding.freshness, binding.key_file):
        with _private_file(path):
            pass
    if any(os.path.samefile(a, b) for a, b in (
            (binding.history, binding.freshness), (binding.history, binding.key_file),
            (binding.freshness, binding.key_file))):
        raise ValueError('independent private files required')
    with closing(sqlite3.connect(binding.history.as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone() != (str(binding.tenant),):
            raise ValueError('tenant not provisioned')
        objects = db.execute('SELECT object FROM media_sources LIMIT 65').fetchall()
        if not (0 if allow_empty else 1) <= len(objects) <= 64:
            raise ValueError('media sources not provisioned')
    with closing(sqlite3.connect(binding.freshness.as_uri() + '?mode=ro', uri=True)) as db:
        if not db.execute('SELECT digest FROM authority_checkpoint WHERE id=1').fetchone():
            raise ValueError('authority checkpoint not provisioned')
        if any(not db.execute('SELECT digest FROM media_checkpoints WHERE object=?', row).fetchone() for row in objects):
            raise ValueError('media checkpoint not provisioned')


def _source(binding):
    for name in ('history_admission', 'statement_source', 'media_source'):
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
    from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
    if binding.postgres_file is not None:
        if binding.postgres_settings is None:
            raise ValueError('unprepared PostgreSQL configuration')
        store=binding.postgres_settings.open()
        store.binding_spec=binding.postgres_settings
    else:
        store = SqliteHistoryStore(binding.history, freshness_path=binding.freshness, require_authority_checkpoint=True)
    try:
        return sys.modules['media_source'].MediaSource(store, str(binding.tenant))
    except BaseException:
        if binding.postgres_file is not None:
            store.close()
        raise


def load_media_bindings(environ=None, *, source_factory=None, store_factory=None, allocation_bindings=None):
    configured = (os.environ if environ is None else environ).get(CONFIG_NAME)
    if configured is None:
        return None
    try:
        with _private_file(_path(configured)) as stream:
            settings = _prepare_settings(parse_settings(stream.read(MAX_CONFIG_BYTES + 1)))
        allocation_sources = {}
        for binding in (allocation_bindings or {}).values():
            key = UUID(binding.tenant)
            spec = (binding.authority, binding.client.origin)
            if key in allocation_sources and allocation_sources[key] != spec:
                raise ValueError('conflicting allocation authority')
            allocation_sources[key] = spec
        secrets = {}
        for row in settings:
            allocation = allocation_sources.get(row.tenant)
            if allocation:
                authority, origin = allocation
                if (not authority.production_ready or authority.tenant != str(row.tenant) or origin != row.origin
                        or not _same_source(row,authority.store)):
                    raise ValueError('allocation and delivery sources differ')
                _provisioned(row, allow_empty=True)
            else:
                _provisioned(row)
            if row.tenant not in secrets:
                with _private_file(row.key_file) as stream:
                    key = stream.read(4097).decode('ascii')
                if re.fullmatch(r'[\x21-\x7e]{1,4096}', key) is None:
                    raise ValueError('invalid storage key')
                secrets[row.tenant] = key
        # All private configuration is checked before constructing clients.
        sources = {}
        for row in settings:
            if row.tenant not in sources:
                source = allocation_sources[row.tenant][0] if row.tenant in allocation_sources else (source_factory or _source)(row)
                if not source.production_ready or source.tenant != str(row.tenant):
                    raise ValueError('protected media source required')
                sources[row.tenant] = source
        from acl_service.infrastructure.private_wrap_store import PrivateWrapStore
        from acl_service.interfaces.api.private_wrap_routes import PrivateWrapBinding
        stores, result = {}, {}
        for row in settings:
            if row.tenant not in stores:
                stores[row.tenant] = (store_factory or PrivateWrapStore)(row.origin, str(row.tenant), secrets[row.tenant])
            result[(row.tenant, row.subject)] = PrivateWrapBinding(
                str(row.tenant), row.reader, sources[row.tenant], stores[row.tenant])
        return result
    except Exception:
        raise RuntimeError('Invalid private media binding configuration') from None
