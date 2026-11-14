"""Single-host durable history backend. Each operation owns its transaction."""
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.relational_history_store import RelationalHistoryStore


class SqliteHistoryStore(RelationalHistoryStore):
    def __init__(self, path: Path, *, freshness_path: Path | None = None,
                 require_authority_checkpoint: bool = False):
        if require_authority_checkpoint and freshness_path is None:
            raise ValueError("authority checkpoint requires separate freshness storage")
        self.require_authority_checkpoint = require_authority_checkpoint
        self.path = path
        self.freshness_path = freshness_path
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS history_accounts (
                principal TEXT PRIMARY KEY NOT NULL, genesis BLOB NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS history_entries (
                principal TEXT NOT NULL REFERENCES history_accounts(principal),
                revision INTEGER NOT NULL, entry BLOB NOT NULL,
                PRIMARY KEY (principal, revision))""")

            db.execute("""CREATE TABLE IF NOT EXISTS history_head_floors (
                principal TEXT PRIMARY KEY NOT NULL REFERENCES history_accounts(principal),
                head INTEGER NOT NULL CHECK (head >= 0))""")

            db.execute("""CREATE TABLE IF NOT EXISTS history_ciphertext (
                principal TEXT NOT NULL REFERENCES history_accounts(principal),
                kind TEXT NOT NULL CHECK(kind IN ('recovery', 'wraps')),
                generation INTEGER NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(principal, kind))""")

    @property
    def has_freshness(self):
        return self.freshness_path is not None

    def _connect(self):
        db = sqlite3.connect(self.path.resolve().as_uri(), uri=True)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @contextmanager
    def _transaction(self, *, write, ciphertext=False, before_commit=None):
        attached = self.freshness_path is not None and (ciphertext or self.require_authority_checkpoint)
        try:
            with closing(self._connect()) as db, db:
                if attached:
                    self._attach_freshness(db)
                # A deferred read can hold freshness while waiting for main,
                # opposite to an attached writer's commit lock order. Reserve
                # both databases before reading either to avoid that deadlock.
                db.execute("BEGIN IMMEDIATE" if write or attached else "BEGIN")
                if self.require_authority_checkpoint:
                    expected = db.execute("SELECT digest FROM freshness.authority_checkpoint WHERE id=1").fetchone()
                    if expected != (authority_digest(db),):
                        raise StoreRejected()
                yield db
                if write and self.require_authority_checkpoint:
                    db.execute("UPDATE freshness.authority_checkpoint SET digest=? WHERE id=1",
                               (authority_digest(db),))
                if before_commit is not None:
                    before_commit()
        except sqlite3.OperationalError as exc:
            if getattr(exc, "sqlite_errorcode", 0) & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                # Rollback/close happened above. Never retry a signed write or
                # expose database details; the caller must refresh its fence.
                raise HistoryConflict("store contention; refresh required") from None
            raise

    def _attach_freshness(self, db):
        if self.freshness_path is None:
            return
        if self.path.samefile(self.freshness_path):
            raise StoreRejected()
        db.execute("ATTACH DATABASE ? AS freshness", (self.freshness_path.resolve().as_uri() + "?mode=rw",))
        for name in ("main", "freshness"):
            if db.execute(f"PRAGMA {name}.journal_mode").fetchone()[0] != "delete":
                raise StoreRejected()
            db.execute(f"PRAGMA {name}.synchronous=EXTRA")

