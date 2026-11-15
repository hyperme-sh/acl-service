"""Contact documents in a provisioned PostgreSQL identity source.

The admission adapter authenticates the principal, signatures and current history
inside the same source transaction. Descriptor bytes are signed public records;
vault bytes are client ciphertext. This store never receives an unlocked keyring.
"""
from dataclasses import dataclass
import hashlib
import json
import re
import secrets

from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore

MAX_REVISION = 9007199254740991
MAX_OWNERS = 4096
LIMITS = {'descriptor': (1, 8192), 'vault': (28, 1024 * 1024)}
PRINCIPAL = re.compile(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}')


def _scope(principal, kind):
    if type(principal) is not str or PRINCIPAL.fullmatch(principal) is None or kind not in LIMITS:
        raise ValueError('invalid contact document scope')


@dataclass(frozen=True)
class ContactDocument:
    revision: int
    nonce: bytes
    payload: bytes


def contact_digest(tenant, source, principal, kind, row):
    _scope(principal, kind)
    minimum, maximum = LIMITS[kind]
    if (type(row) is not ContactDocument or type(row.revision) is not int
            or not 1 <= row.revision <= MAX_REVISION or type(row.nonce) is not bytes
            or len(row.nonce) != 32 or type(row.payload) is not bytes
            or not minimum <= len(row.payload) <= maximum):
        raise ValueError('invalid contact document')
    context = json.dumps(['s3rch-contact-document-v1', tenant, source, principal, kind, row.revision],
                         separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(len(context).to_bytes(8, 'big') + context + row.nonce + row.payload).digest()


def install_contact_journal(url, *, history_schema, checkpoint_schema, tenant, source, active_media_index=False):
    """Explicit absence-only installation; never invoked by a runtime loader."""
    store = PostgresHistoryStore(url, history_schema=history_schema,
        checkpoint_schema=checkpoint_schema, tenant=tenant, source=source, active_media_index=active_media_index)
    try:
        with store._transaction(write=True) as db:
            db.execute('CREATE TABLE contact_documents (principal TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN (\'descriptor\',\'vault\')), revision BIGINT NOT NULL CHECK(revision>0), nonce BYTEA NOT NULL, payload BYTEA NOT NULL, PRIMARY KEY(principal,kind))')
            db.execute('CREATE TABLE freshness.contact_checkpoints (principal TEXT NOT NULL, kind TEXT NOT NULL, digest BYTEA NOT NULL, PRIMARY KEY(principal,kind))')
    finally:
        store.close()


class ContactJournal:
    def __init__(self, store):
        if not isinstance(store, PostgresHistoryStore):
            raise ValueError('PostgreSQL contact source required')
        self.store = store
        with store._transaction(write=False) as db:
            for table in ('contact_documents', 'freshness.contact_checkpoints'):
                db.execute(f'SELECT 1 FROM {table} LIMIT 1')

    def _db(self, db):
        if (getattr(db, 'origin', None) is not self.store or db.history != self.store.history_schema
                or db.checkpoint != self.store.checkpoint_schema):
            raise ValueError('contact transaction scope changed')

    def _digest(self, principal, kind, row):
        return contact_digest(self.store.tenant, self.store.source, principal, kind, row)

    def read(self, db, principal, kind):
        self._db(db)
        _scope(principal, kind)
        raw = db.execute('SELECT revision,nonce,payload FROM contact_documents WHERE principal=? AND kind=?',
                         (principal, kind)).fetchone()
        checkpoint = db.execute('SELECT digest FROM freshness.contact_checkpoints WHERE principal=? AND kind=?',
                                (principal, kind)).fetchone()
        if raw is None:
            if checkpoint is not None:
                raise HistoryConflict('contact document missing')
            return None
        row = ContactDocument(*raw)
        if checkpoint != (self._digest(principal, kind, row),):
            raise HistoryConflict('contact checkpoint mismatch')
        return row

    def write(self, db, principal, kind, expected, payload):
        """CAS only within the caller's locked, authorized source transaction.

        No automatic retry or destructive delete. Disabling a descriptor or
        changing contacts/blocks commits a new document and retains its floor.
        """
        self._db(db)
        _scope(principal, kind)
        if expected is not None:
            self._digest(principal, kind, expected)
        current = self.read(db, principal, kind)
        if current != expected:
            raise HistoryConflict('contact document changed')
        saved = ContactDocument(1 if current is None else current.revision + 1, secrets.token_bytes(32), payload)
        digest = self._digest(principal, kind, saved)
        if current is None:
            owners = db.execute('SELECT COUNT(DISTINCT principal) FROM (SELECT principal FROM contact_documents UNION SELECT principal FROM freshness.contact_checkpoints) AS owners').fetchone()[0]
            existing = db.execute('SELECT 1 FROM (SELECT principal FROM contact_documents UNION SELECT principal FROM freshness.contact_checkpoints) AS owners WHERE principal=?', (principal,)).fetchone()
            if existing is None and owners >= MAX_OWNERS:
                raise ValueError('contact journal capacity')
            db.execute('INSERT INTO contact_documents VALUES(?,?,?,?,?)',
                       (principal, kind, saved.revision, saved.nonce, saved.payload))
            db.execute('INSERT INTO freshness.contact_checkpoints VALUES(?,?,?)', (principal, kind, digest))
        else:
            updated = db.execute('UPDATE contact_documents SET revision=?,nonce=?,payload=? WHERE principal=? AND kind=? AND revision=?',
                                 (saved.revision, saved.nonce, saved.payload, principal, kind, current.revision))
            if updated.rowcount != 1:
                raise HistoryConflict('contact document changed')
            updated = db.execute('UPDATE freshness.contact_checkpoints SET digest=? WHERE principal=? AND kind=?',
                                 (digest, principal, kind))
            if updated.rowcount != 1:
                raise HistoryConflict('contact checkpoint missing')
        return saved
