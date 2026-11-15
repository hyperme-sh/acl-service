"""Independent group documents inside an already-provisioned PostgreSQL source.

Callers must verify group signatures and authorization in the same source
transaction before writing. This module stores no keys and makes no access
or epoch decisions. Existing media-only processes remain compatible.
"""
from dataclasses import dataclass
import hashlib
import json
import secrets

from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore

MAX_DOCUMENT = 4 * 1024 * 1024
MAX_GROUPS = 64
MAX_REVISION = 9007199254740991


def _scope(predicate, set_id):
    if predicate not in ('same-group', 'named-circle') or type(set_id) is not str or not set_id.startswith('set_') or not 5 <= len(set_id) <= 512:
        raise ValueError('invalid group journal scope')


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@dataclass(frozen=True)
class GroupDocument:
    revision: int
    nonce: bytes
    document: bytes


def group_checkpoint_digest(tenant, predicate, set_id, row):
    _scope(predicate, set_id)
    if type(row) is not GroupDocument or type(row.revision) is not int or not 1 <= row.revision <= MAX_REVISION or type(row.nonce) is not bytes or len(row.nonce) != 32 or type(row.document) is not bytes or not 1 <= len(row.document) <= MAX_DOCUMENT:
        raise ValueError('invalid group journal document')
    context = _encoded(['group-media-v1', tenant, predicate, set_id, row.revision])
    return hashlib.sha256(len(context).to_bytes(8, 'big') + context + row.nonce + row.document).digest()


def install_group_media_journal(url, *, history_schema, checkpoint_schema, tenant, source, active_media_index=False):
    """Explicit absence-only setup. No runtime loader calls this function."""
    store = PostgresHistoryStore(url, history_schema=history_schema, checkpoint_schema=checkpoint_schema,
        tenant=tenant, source=source, active_media_index=active_media_index)
    try:
        with store._transaction(write=True) as db:
            # No IF NOT EXISTS or repair path: partial installation rolls back.
            db.execute('CREATE TABLE group_media_sources (predicate TEXT NOT NULL, set_id TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>0), nonce BYTEA NOT NULL, document BYTEA NOT NULL, PRIMARY KEY(predicate,set_id))')
            db.execute('CREATE TABLE freshness.group_media_checkpoints (predicate TEXT NOT NULL, set_id TEXT NOT NULL, digest BYTEA NOT NULL, PRIMARY KEY(predicate,set_id))')
    finally:
        store.close()


class GroupMediaJournal:
    def __init__(self, store, *, transaction=None):
        if not isinstance(store, PostgresHistoryStore):
            raise ValueError('PostgreSQL group source required')
        self.store = store
        def check(db):
            self._db(db)
            for table in ('group_media_sources', 'freshness.group_media_checkpoints'):
                db.execute(f'SELECT 1 FROM {table} LIMIT 1')
        if transaction is not None:
            check(transaction)
        else:
            with store._transaction(write=False) as db:check(db)

    def _db(self, db):
        if getattr(db, 'origin', None) is not self.store or db.history != self.store.history_schema or db.checkpoint != self.store.checkpoint_schema:
            raise ValueError('group journal transaction scope changed')

    def scopes(self, db, page):
        """Bounded candidates only; callers authorize every returned document."""
        self._db(db)
        if type(page) is not int or not 0 <= page < 16:
            raise ValueError('invalid group page')
        return db.execute('SELECT predicate,set_id FROM (SELECT predicate,set_id FROM group_media_sources UNION SELECT predicate,set_id FROM freshness.group_media_checkpoints) AS candidates ORDER BY predicate,set_id LIMIT 4 OFFSET ?', (page * 4,)).fetchall()

    def read(self, db, predicate, set_id):
        self._db(db)
        _scope(predicate, set_id)
        row = db.execute('SELECT revision,nonce,document FROM group_media_sources WHERE predicate=? AND set_id=?', (predicate, set_id)).fetchone()
        checkpoint = db.execute('SELECT digest FROM freshness.group_media_checkpoints WHERE predicate=? AND set_id=?', (predicate, set_id)).fetchone()
        if row is None:
            if checkpoint is not None:
                raise HistoryConflict('group document missing')
            return None
        held = GroupDocument(*row)
        if checkpoint != (group_checkpoint_digest(self.store.tenant, predicate, set_id, held),):
            raise HistoryConflict('group checkpoint mismatch')
        return held

    def write(self, db, predicate, set_id, expected, document):
        """CAS under the caller's source lock; never replace unverified state."""
        self._db(db)
        if expected is not None:
            group_checkpoint_digest(self.store.tenant, predicate, set_id, expected)
        current = self.read(db, predicate, set_id)
        if current != expected:
            raise HistoryConflict('group document changed')
        if type(document) is not dict:
            raise ValueError('group document object required')
        payload = _encoded(document)
        revision = 1 if current is None else current.revision + 1
        saved = GroupDocument(revision, secrets.token_bytes(32), payload)
        digest = group_checkpoint_digest(self.store.tenant, predicate, set_id, saved)
        if current is None:
            count = db.execute('SELECT COUNT(*) FROM (SELECT predicate,set_id FROM group_media_sources UNION SELECT predicate,set_id FROM freshness.group_media_checkpoints) AS candidates').fetchone()[0]
            if count >= MAX_GROUPS:
                raise ValueError('group journal capacity')
            db.execute('INSERT INTO group_media_sources VALUES(?,?,?,?,?)', (predicate, set_id, revision, saved.nonce, payload))
            db.execute('INSERT INTO freshness.group_media_checkpoints VALUES(?,?,?)', (predicate, set_id, digest))
        else:
            updated = db.execute('UPDATE group_media_sources SET revision=?,nonce=?,document=? WHERE predicate=? AND set_id=? AND revision=?', (revision, saved.nonce, payload, predicate, set_id, current.revision))
            if updated.rowcount != 1:
                raise HistoryConflict('group document changed')
            updated = db.execute('UPDATE freshness.group_media_checkpoints SET digest=? WHERE predicate=? AND set_id=?', (digest, predicate, set_id))
            if updated.rowcount != 1:
                raise HistoryConflict('group checkpoint missing')
        return saved
