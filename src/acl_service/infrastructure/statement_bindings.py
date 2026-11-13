"""Default-off bindings to already provisioned, protected statement stores."""
from contextlib import closing
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from uuid import UUID

CONFIG_NAME = 'SOCIACL_STATEMENT_BINDINGS_FILE'
MAX_CONFIG_BYTES = 65536

@dataclass(frozen=True)
class BindingSettings:
    tenant: UUID
    subject: str
    scope: str
    history: Path
    freshness: Path


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate configuration field')
    return result


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError('invalid path')
    path = Path(value)
    if not path.is_absolute() or str(path) != value or '..' in path.parts:
        raise ValueError('canonical absolute path required')
    return path


def parse_settings(data: bytes) -> tuple[BindingSettings, ...]:
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError('oversized configuration')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=_unique)
    if (not isinstance(value, dict) or set(value) != {'version', 'bindings'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['bindings'], list) or not 1 <= len(value['bindings']) <= 64):
        raise ValueError('invalid configuration')
    result, keys, stores = [], set(), {}
    for row in value['bindings']:
        if not isinstance(row, dict) or set(row) != {'tenant', 'subject', 'scope', 'historyFile', 'freshnessFile'}:
            raise ValueError('invalid binding')
        if not isinstance(row['tenant'], str):
            raise ValueError('canonical tenant required')
        tenant = UUID(row['tenant'])
        if not tenant.int or str(tenant) != row['tenant']:
            raise ValueError('canonical tenant required')
        subject, scope = row['subject'], row['scope']
        if (not isinstance(subject, str) or not re.fullmatch(r'[\x21-\x7e]{1,256}', subject)
                or not isinstance(scope, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', scope)):
            raise ValueError('invalid binding identity')
        history, freshness = _path(row['historyFile']), _path(row['freshnessFile'])
        key = (tenant, subject, scope)
        if key in keys or history == freshness:
            raise ValueError('duplicate binding or store')
        pair = (tenant, history, freshness)
        for path in (history, freshness):
            if path in stores and stores[path] != pair:
                raise ValueError('store has conflicting tenant or checkpoint')
            stores[path] = pair
        keys.add(key)
        result.append(BindingSettings(tenant, subject, scope, history, freshness))
    return tuple(result)


def _private_file(path: Path):
    if path.resolve() != path:
        raise ValueError('symlink paths are not allowed')
    for parent in path.parents:
        info = parent.stat()
        if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
            raise ValueError('untrusted parent directory')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o077:
            raise ValueError('private regular file required')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def _provisioned(binding):
    for path in (binding.history, binding.freshness):
        with _private_file(path):
            pass
    if os.path.samefile(binding.history, binding.freshness):
        raise ValueError('independent stores required')
    with closing(sqlite3.connect(binding.history.as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone() != (str(binding.tenant),):
            raise ValueError('tenant is not provisioned')
        if db.execute('SELECT 1 FROM statement_scopes WHERE scope=?', (binding.scope,)).fetchone() != (1,):
            raise ValueError('scope is not provisioned')
    with closing(sqlite3.connect(binding.freshness.as_uri() + '?mode=ro', uri=True)) as db:
        if not db.execute('SELECT digest FROM authority_checkpoint WHERE id=1').fetchone():
            raise ValueError('authority checkpoint is not provisioned')
        if not db.execute('SELECT digest FROM statement_checkpoints WHERE scope=?', (binding.scope,)).fetchone():
            raise ValueError('graph checkpoint is not provisioned')


def _source(binding, *, delegations=False):
    # Only load the verifier shipped in the image, never a configured module path.
    names = ('history_admission', 'statement_source') + (('delegation_source',) if delegations else ())
    for name in names:
        path = Path('/opt/acl-admission') / (name + '.py')
        existing = sys.modules.get(name)
        if existing is not None:
            if Path(existing.__file__) != path:
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
    store = SqliteHistoryStore(binding.history, freshness_path=binding.freshness, require_authority_checkpoint=True)
    source_type = sys.modules['delegation_source'].DelegationSource if delegations else sys.modules['statement_source'].StatementSource
    return source_type(store, str(binding.tenant))


def load_statement_bindings(environ=None, *, source_factory=None):
    env = os.environ if environ is None else environ
    configured = env.get(CONFIG_NAME)
    if configured is None:
        return None
    try:
        with _private_file(_path(configured)) as stream:
            settings = parse_settings(stream.read(MAX_CONFIG_BYTES + 1))
        # Validate every existing store before constructing any source. This path
        # never creates a database, enrolls an identity or provisions a graph.
        for binding in settings:
            _provisioned(binding)
        from acl_service.interfaces.api.statement_routes import StatementBinding
        sources, result = {}, {}
        for binding in settings:
            key = (binding.tenant, binding.history, binding.freshness)
            if key not in sources:
                sources[key] = (source_factory or _source)(binding)
            source = sources[key]
            if not source.production_ready or source.tenant != str(binding.tenant):
                raise ValueError('protected source required')
            result[(binding.tenant, binding.subject, binding.scope)] = StatementBinding(binding.scope, source)
        return result
    except Exception:
        # Do not print private subjects, paths, file contents or verifier inputs.
        raise RuntimeError('Invalid statement source binding configuration') from None
