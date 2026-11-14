"""Already-provisioned PostgreSQL history and independently restored checkpoints."""
from contextlib import contextmanager
import re
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError

from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.infrastructure.relational_history_store import RelationalHistoryStore


def scope_name(value):
    if type(value) is not str or re.fullmatch(r'acl_[a-z0-9_]{1,48}', value) is None:
        raise ValueError('invalid protected schema')
    return value


class _Connection:
    """Adapt only the fixed internal positional statements; never request SQL."""
    def __init__(self, connection, history, checkpoint):
        self.connection, self.history, self.checkpoint = connection, history, checkpoint

    def execute(self, statement, parameters=()):
        from sqlalchemy import text
        statement = statement.replace('main.', self.history + '.').replace('freshness.', self.checkpoint + '.')
        pieces = statement.split('?')
        if len(pieces) != len(parameters) + 1:
            raise ValueError('invalid internal SQL parameters')
        sql = pieces[0] + ''.join(f':p{i}' + part for i, part in enumerate(pieces[1:]))
        return self.connection.execute(text(sql), {f'p{i}': value for i, value in enumerate(parameters)})

    def executemany(self, statement, rows):
        for row in rows:
            self.execute(statement, row)


class PostgresHistoryStore(RelationalHistoryStore):
    """No DDL, enrollment, migration or checkpoint repair during construction.

    Each transaction locks an existing source marker before reading either
    scope. All source writers use this lock; stale fences remain application
    conflicts. Missing markers or mismatched snapshots fail closed.
    """
    require_authority_checkpoint = True
    has_freshness = True
    provisioned_media = True

    def __init__(self, url, *, history_schema, checkpoint_schema, tenant, source):
        self.history_schema = scope_name(history_schema)
        self.checkpoint_schema = scope_name(checkpoint_schema)
        if self.history_schema == self.checkpoint_schema:
            raise ValueError('independent schemas required')
        self.tenant, self.source = str(UUID(tenant)), str(UUID(source))
        if self.tenant != tenant or self.source != source or not UUID(tenant).int or not UUID(source).int:
            raise ValueError('canonical source and tenant required')
        self.engine = create_engine(url, pool_pre_ping=True, connect_args={'connect_timeout': 3})
        if self.engine.dialect.name != 'postgresql':
            self.engine.dispose()
            raise ValueError('PostgreSQL required')
        try:
            with self._transaction(write=False) as db:
                for table in ('history_ciphertext', 'statement_tenant', 'media_sources', 'media_allocations',
                              'freshness.ciphertext_heads', 'freshness.media_checkpoints', 'freshness.media_allocations'):
                    db.execute(f'SELECT 1 FROM {table} LIMIT 1')
                if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone() != (tenant,):
                    raise StoreRejected()
        except BaseException:
            self.engine.dispose()
            raise

    def close(self):
        self.engine.dispose()

    @contextmanager
    def _transaction(self, *, write, ciphertext=False, before_commit=None):
        try:
            with self.engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL lock_timeout = '1000ms'")
                connection.exec_driver_sql("SET LOCAL statement_timeout = '3000ms'")
                connection.exec_driver_sql(f'SET LOCAL search_path = "{self.history_schema}", pg_catalog')
                db = _Connection(connection, self.history_schema, self.checkpoint_schema)
                expected = (self.tenant, self.source, 1)
                marker = db.execute('SELECT tenant,source,version FROM source_marker WHERE id=1 FOR UPDATE').fetchone()
                checkpoint = db.execute('SELECT tenant,source,version FROM freshness.source_marker WHERE id=1 FOR UPDATE').fetchone()
                if marker != expected or checkpoint != expected:
                    raise StoreRejected()
                if db.execute('SELECT digest FROM freshness.authority_checkpoint WHERE id=1').fetchone() != (authority_digest(db),):
                    raise StoreRejected()
                yield db
                if write:
                    updated = db.execute('UPDATE freshness.authority_checkpoint SET digest=? WHERE id=1', (authority_digest(db),))
                    if updated.rowcount != 1:
                        raise StoreRejected()
                if before_commit is not None:
                    before_commit()
        except DBAPIError as exc:
            if getattr(exc.orig, 'sqlstate', None) in ('55P03', '40001', '40P01', '57014'):
                raise HistoryConflict('store contention; refresh required') from None
            raise StoreRejected() from None
