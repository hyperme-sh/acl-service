"""Single-host durable history backend. Each operation owns its transaction."""
import sqlite3
from contextlib import closing
from pathlib import Path

from acl_service.domain.history_store import HistoryConflict, HistorySnapshot


class SqliteHistoryStore:
    def __init__(self, path: Path):
        self.path = path
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS history_accounts (
                principal TEXT PRIMARY KEY NOT NULL, genesis BLOB NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS history_entries (
                principal TEXT NOT NULL REFERENCES history_accounts(principal),
                revision INTEGER NOT NULL, entry BLOB NOT NULL,
                PRIMARY KEY (principal, revision))""")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def enroll(self, principal: str, genesis: bytes) -> None:
        if not principal or not isinstance(genesis, bytes) or not genesis:
            raise ValueError("missing principal or genesis")
        with closing(self._connect()) as db, db:
            inserted = db.execute(
                "INSERT INTO history_accounts VALUES (?, ?) ON CONFLICT(principal) DO NOTHING",
                (principal, genesis),
            )
            if inserted.rowcount != 1:
                raise HistoryConflict("principal already enrolled")

    def append(self, principal: str, expected_revision: int, entry: bytes) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("invalid revision")
        if not isinstance(entry, bytes) or not entry:
            raise ValueError("missing history entry")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT (SELECT MAX(revision) FROM history_entries WHERE principal = ?)
                   FROM history_accounts WHERE principal = ?""", (principal, principal)
            ).fetchone()
            if row is None or (row[0] or 0) != expected_revision:
                raise HistoryConflict("missing account or stale revision")
            db.execute("INSERT INTO history_entries VALUES (?, ?, ?)",
                       (principal, expected_revision + 1, entry))

    def read(self, principal: str) -> HistorySnapshot | None:
        with closing(self._connect()) as db, db:
            db.execute("BEGIN")
            account = db.execute("SELECT genesis FROM history_accounts WHERE principal = ?",
                                 (principal,)).fetchone()
            if account is None:
                return None
            entries = db.execute(
                "SELECT entry FROM history_entries WHERE principal = ? ORDER BY revision",
                (principal,),
            )
            return HistorySnapshot(principal, account[0], tuple(row[0] for row in entries))
