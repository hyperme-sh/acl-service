"""Read-only statement snapshot for the dedicated genesis-only TEST vault."""
import hashlib
import json
import re
import time
from uuid import UUID

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique
from acl_service.interfaces.api.statement_routes import StatementBinding

CONFIG = 'SOCIACL_TEST_VAULT_STATEMENT_FILE'
SCOPE = 's3rch-native-vault'


class VaultStatements:
    production_ready = True

    def __init__(self, settings, owner, clock=time.time):
        self.settings, self.tenant, self.owner, self.clock = settings, settings.tenant, owner, clock

    def read(self, scope, at, cancel):
        if scope != SCOPE:
            raise AdmissionRejected('vault statement scope differs')
        if type(at) is not int or at < 0 or int(self.clock()) != at:
            raise HistoryConflict('vault snapshot evaluation expired')
        cancel()
        store = self.settings.open(read_snapshot=True)
        try:
            # The PostgreSQL transaction checks both markers and the independent
            # digest before exposing the enrolled history.
            with store._transaction(write=False, read_snapshot=True) as db:
                rows = list(db.execute('SELECT principal,genesis FROM history_accounts LIMIT 2'))
                if (len(rows) != 1 or rows[0][0] != self.owner or len(rows[0][1]) > 16384
                        or db.execute('SELECT 1 FROM history_entries LIMIT 1').fetchone()):
                    raise AdmissionRejected('dedicated genesis history required')
                raw = rows[0][1]
                genesis = json.loads(raw, object_pairs_hook=_unique)
                if (genesis.get('principal') != self.owner or genesis.get('kind') != 'genesis-epub'
                        or type(genesis.get('issuedAt')) is not int or not 0 <= genesis['issuedAt'] <= at):
                    raise AdmissionRejected('vault genesis binding differs')
                cancel()
                if int(self.clock()) != at:
                    raise HistoryConflict('vault snapshot evaluation expired')
                return {'fence': hashlib.sha256(raw).hexdigest(),
                        'snapshot': {'completeThrough': at, 'rows': [],
                                     'history': {'completeThrough': at, 'links': [], 'accounts': [
                                         {'principal': self.owner, 'genesisEpubBindings': [genesis],
                                          'revocations': [], 'rotations': []}]}}}
        finally:
            store.close()

    def append(self, scope, at, fence, rows, cancel):
        raise AdmissionRejected('vault snapshot is read-only')


def add_vault_statement_binding(bindings, env):
    if CONFIG not in env:
        return bindings
    try:
        with _private_file(_path(env[CONFIG])) as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError()
        value = json.loads(raw, object_pairs_hook=_unique)
        if set(value) != {'version', 'tenant', 'subject', 'owner', 'postgresFile'} or type(value['version']) is not int or value['version'] != 1:
            raise ValueError()
        tenant = UUID(value['tenant'])
        if (not tenant.int or str(tenant) != value['tenant']
                or not re.fullmatch(r'[\x21-\x7e]{1,256}', value['subject'])
                or not re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}', value['owner'])):
            raise ValueError()
        settings = read_postgres_settings(_path(value['postgresFile']), tenant)
        if (settings.history_schema, settings.checkpoint_schema, settings.active_media_index) != (
                'acl_s3rch_vault_history', 'acl_s3rch_vault_checkpoint', False):
            raise ValueError()
        result = dict(bindings or {})
        key = (tenant, value['subject'], SCOPE)
        if key in result:
            raise ValueError()
        result[key] = StatementBinding(SCOPE, VaultStatements(settings, value['owner']))
        return result
    except Exception:
        raise RuntimeError('Invalid TEST vault statement binding') from None
