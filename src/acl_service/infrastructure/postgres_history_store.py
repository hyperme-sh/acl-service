"""Already-provisioned PostgreSQL history and independently restored checkpoints."""
from contextlib import contextmanager
import hashlib
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
    def __init__(self, connection, history, checkpoint, *, origin=None):
        self.connection, self.history, self.checkpoint = connection, history, checkpoint
        self.origin = origin

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
    provisioned_statements = True

    def __init__(self, url, *, history_schema, checkpoint_schema, tenant, source, active_media_index=False,
                 read_snapshot=False, statements=False):
        if type(active_media_index) is not bool:raise ValueError('invalid media index mode')
        if type(statements) is not bool or (statements and active_media_index):
            raise ValueError('invalid statement source mode')
        self.active_media_index=active_media_index
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
            with self._transaction(write=False, read_snapshot=read_snapshot) as db:
                common = ('history_ciphertext', 'statement_tenant', 'freshness.ciphertext_heads')
                protected = (('statement_scopes', 'freshness.statement_checkpoints') if statements else
                             ('media_sources', 'media_allocations', 'freshness.media_checkpoints', 'freshness.media_allocations'))
                for table in common + protected:
                    db.execute(f'SELECT 1 FROM {table} LIMIT 1')
                if self.active_media_index:db.execute('SELECT 1 FROM freshness.media_active LIMIT 1')
                if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone() != (tenant,):
                    raise StoreRejected()
        except BaseException:
            self.engine.dispose()
            raise

    def close(self):
        self.engine.dispose()

    def enroll_first_media_owner(self, principal, genesis, *, before_commit, allow_exact_retry=False):
        """Bootstrap an empty source, with optional idempotence for an exact prior genesis."""
        if not principal or type(genesis) is not bytes or not genesis or not callable(before_commit):
            raise ValueError('verified first owner required')
        with self._transaction(write=True,before_commit=before_commit) as db:
            before_commit()
            if allow_exact_retry:
                held = db.execute('SELECT genesis FROM history_accounts WHERE principal=?', (principal,)).fetchone()
                if (held == (genesis,) and db.execute(
                        'SELECT 1 FROM history_accounts WHERE principal<>? LIMIT 1',
                        (principal,),
                ).fetchone() is None):
                    return False
            for table in ('history_accounts','history_entries','history_head_floors','history_ciphertext',
                          'media_sources','media_allocations','freshness.ciphertext_heads',
                          'freshness.media_checkpoints','freshness.media_allocations'):
                if db.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone() is not None:
                    raise HistoryConflict('first owner requires empty source')
            if self.active_media_index and db.execute('SELECT 1 FROM freshness.media_active LIMIT 1').fetchone() is not None:
                raise HistoryConflict('first owner requires empty source')
            db.execute('INSERT INTO history_accounts VALUES (?,?)',(principal,genesis))
            db.executemany('INSERT INTO freshness.ciphertext_heads VALUES(?,?,0,?)',
                           [(principal,kind,hashlib.sha256(b'').digest()) for kind in ('recovery','wraps')])
            if allow_exact_retry:
                return True

    def enroll_media_fixture(self, operator, principal, genesis, *, before_commit):
        """Add one verified account and its checkpoints to an existing source."""
        if (not operator or not principal or operator == principal or type(genesis) is not bytes
                or not genesis or not callable(before_commit)):
            raise ValueError('verified media fixture required')
        with self._transaction(write=True, before_commit=before_commit) as db:
            before_commit()
            if not db.execute('SELECT 1 FROM history_accounts WHERE principal=?', (operator,)).fetchone():
                raise HistoryConflict('original operator is not enrolled')
            held = db.execute('SELECT genesis FROM history_accounts WHERE principal=?', (principal,)).fetchone()
            if held is not None:
                if held[0] != genesis:
                    raise HistoryConflict('fixture already enrolled with different genesis')
                return False
            db.execute('INSERT INTO history_accounts VALUES (?,?)', (principal, genesis))
            empty = hashlib.sha256(b'').digest()
            db.executemany('INSERT INTO freshness.ciphertext_heads VALUES(?,?,0,?)',
                           [(principal, kind, empty) for kind in ('recovery', 'wraps')])
            return True

    @contextmanager
    def _transaction(self, *, write, ciphertext=False, before_commit=None, read_snapshot=False):
        if write and read_snapshot:
            raise ValueError('read-only snapshot cannot write history')
        try:
            with self.engine.begin() as connection:
                if read_snapshot:
                    connection.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                connection.exec_driver_sql("SET LOCAL lock_timeout = '1000ms'")
                connection.exec_driver_sql("SET LOCAL statement_timeout = '3000ms'")
                connection.exec_driver_sql(f'SET LOCAL search_path = "{self.history_schema}", pg_catalog')
                db = _Connection(connection, self.history_schema, self.checkpoint_schema, origin=self)
                expected = (self.tenant, self.source, 2 if self.active_media_index else 1)
                # A repeatable snapshot reads the markers, checkpoint and rows
                # from the same committed view without taking writer locks.
                lock = '' if read_snapshot else ' FOR UPDATE'
                marker = db.execute('SELECT tenant,source,version FROM source_marker WHERE id=1' + lock).fetchone()
                checkpoint = db.execute('SELECT tenant,source,version FROM freshness.source_marker WHERE id=1' + lock).fetchone()
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
