"""Atomic group allocation consumption with an independent checkpoint."""
from uuid import UUID

from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.group_media_journal import _scope
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore


def install_group_allocation_journal(url, **spec):
    """Explicit absence-only setup; never invoked by runtime loading."""
    store = PostgresHistoryStore(url, **spec)
    try:
        with store._transaction(write=True) as db:
            for table in ('group_allocations', 'freshness.group_allocations'):
                db.execute(f'CREATE TABLE {table} (allocation TEXT PRIMARY KEY, predicate TEXT NOT NULL, set_id TEXT UNIQUE NOT NULL, digest BYTEA NOT NULL)')
    finally:
        store.close()


class GroupAllocationJournal:
    """The caller verifies current authority and proof inside the same transaction.

    This index and the group document update must commit together. An allocation
    or set cannot be reused under another predicate, source or signed grant.
    """
    def __init__(self, store):
        if not isinstance(store, PostgresHistoryStore):
            raise ValueError('PostgreSQL group allocation source required')
        self.store = store
        with store._transaction(write=False) as db:
            for table in ('group_allocations', 'freshness.group_allocations'):
                db.execute(f'SELECT 1 FROM {table} LIMIT 1')

    def consume(self, db, allocation, predicate, set_id, digest):
        if getattr(db, 'origin', None) is not self.store or db.history != self.store.history_schema or db.checkpoint != self.store.checkpoint_schema:
            raise ValueError('group allocation transaction scope changed')
        _scope(predicate, set_id)
        if type(allocation) is not str or str(UUID(allocation)) != allocation or not UUID(allocation).int:
            raise ValueError('invalid group allocation identifier')
        if type(digest) is not bytes or len(digest) != 32:
            raise ValueError('invalid group allocation digest')
        expected = (allocation, predicate, set_id, digest)
        rows = []
        for table in ('group_allocations', 'freshness.group_allocations'):
            rows.append(db.execute(f'SELECT allocation,predicate,set_id,digest FROM {table} WHERE allocation=? OR set_id=?', (allocation, set_id)).fetchall())
        if rows[0] or rows[1]:
            if rows != [[expected], [expected]]:
                raise HistoryConflict('group allocation scope or checkpoint mismatch')
            return False
        count = db.execute('SELECT COUNT(*) FROM (SELECT allocation FROM group_allocations UNION SELECT allocation FROM freshness.group_allocations) AS candidates').fetchone()[0]
        if count >= 64:
            raise HistoryConflict('group allocation capacity')
        for table in ('group_allocations', 'freshness.group_allocations'):
            db.execute(f'INSERT INTO {table} VALUES(?,?,?,?)', expected)
        return True
