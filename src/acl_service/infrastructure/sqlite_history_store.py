"""Single-host durable history backend. Each operation owns its transaction."""
import hashlib
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.domain.history_store import HistoryConflict, HistorySnapshot
from acl_service.domain.keyring_store import MAX_GENERATION, StoreKind, StoreRejected


class SqliteHistoryStore:
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

    def _connect(self):
        db = sqlite3.connect(self.path.resolve().as_uri(), uri=True)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @contextmanager
    def _transaction(self, *, write, ciphertext=False):
        with closing(self._connect()) as db, db:
            if ciphertext or self.require_authority_checkpoint:
                self._attach_freshness(db)
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if self.require_authority_checkpoint:
                expected = db.execute("SELECT digest FROM freshness.authority_checkpoint WHERE id=1").fetchone()
                if expected != (authority_digest(db),):
                    raise StoreRejected()
            yield db
            if write and self.require_authority_checkpoint:
                db.execute("UPDATE freshness.authority_checkpoint SET digest=? WHERE id=1",
                           (authority_digest(db),))

    def enroll(self, principal: str, genesis: bytes) -> None:
        if not principal or not isinstance(genesis, bytes) or not genesis:
            raise ValueError("missing principal or genesis")
        with self._transaction(write=True) as db:
            inserted = db.execute(
                "INSERT INTO history_accounts VALUES (?, ?) ON CONFLICT(principal) DO NOTHING",
                (principal, genesis),
            )
            if inserted.rowcount != 1:
                raise HistoryConflict("principal already enrolled")
            if self.require_authority_checkpoint:
                db.executemany("INSERT INTO freshness.ciphertext_heads VALUES(?,?,0,?)",
                               [(principal, kind, hashlib.sha256(b"").digest()) for kind in ("recovery", "wraps")])

    def append(self, principal: str, expected_revision: int, entry: bytes, *,
               authority_revision: int | None = None, verified_rotation: int | None = None) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("invalid revision")
        if not isinstance(entry, bytes) or not entry:
            raise ValueError("missing history entry")
        with self._transaction(write=True) as db:
            if authority_revision is not None and authority_revision != self._authority_revision(db):
                raise HistoryConflict("authority changed")
            row = db.execute(
                """SELECT (SELECT MAX(revision) FROM history_entries WHERE principal = ?)
                   FROM history_accounts WHERE principal = ?""", (principal, principal)
            ).fetchone()
            if row is None or (row[0] or 0) != expected_revision:
                raise HistoryConflict("missing account or stale revision")
            db.execute("INSERT INTO history_entries VALUES (?, ?, ?)",
                       (principal, expected_revision + 1, entry))
            if verified_rotation is not None:
                self._observe_floor(db, principal, verified_rotation)

    def read(self, principal: str) -> HistorySnapshot | None:
        with self._transaction(write=False) as db:
            account = db.execute("SELECT genesis FROM history_accounts WHERE principal = ?",
                                 (principal,)).fetchone()
            if account is None:
                return None
            entries = db.execute(
                "SELECT entry FROM history_entries WHERE principal = ? ORDER BY revision",
                (principal,),
            )
            return HistorySnapshot(principal, account[0], tuple(row[0] for row in entries))

    def observe_head(self, principal: str, head: int, *, authority_revision: int) -> None:
        with self._transaction(write=True) as db:
            if authority_revision != self._authority_revision(db):
                raise HistoryConflict("authority changed")
            self._observe_floor(db, principal, head)

    @staticmethod
    def _observe_floor(db, principal, head):
        if type(head) is not int or not 0 <= head <= MAX_GENERATION:
            raise StoreRejected()
        updated = db.execute("""
            INSERT INTO history_head_floors(principal, head)
            SELECT principal, ? FROM history_accounts WHERE principal = ?
            ON CONFLICT(principal) DO UPDATE SET head = excluded.head
            WHERE excluded.head >= history_head_floors.head
            """, (head, principal))
        if updated.rowcount != 1:
            raise StoreRejected()

    @staticmethod
    def _authority_revision(db):
        # Both tables are immutable and append-only, including pre-upgrade rows.
        return db.execute("""SELECT (SELECT COUNT(*) FROM history_accounts) +
                                    (SELECT COUNT(*) FROM history_entries)""").fetchone()[0]

    def read_authority(self) -> tuple[int, dict[str, HistorySnapshot]]:
        with self._transaction(write=False) as db:
            revision = self._authority_revision(db)
            accounts = dict(db.execute("SELECT principal, genesis FROM history_accounts"))
            entries = {p: [] for p in accounts}
            for owner, raw in db.execute(
                "SELECT principal, entry FROM history_entries ORDER BY principal, revision"
            ):
                entries[owner].append(raw)
            return revision, {
                p: HistorySnapshot(p, genesis, tuple(entries[p])) for p, genesis in accounts.items()
            }

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

    def _ciphertext_snapshot(self, db, principal, kind):
        row = db.execute("SELECT generation, payload FROM main.history_ciphertext "
                         "WHERE principal=? AND kind=?", (principal, kind)).fetchone()
        generation, payload = row if row is not None else (0, b"")
        if self.freshness_path is not None:
            expected = db.execute("SELECT generation, digest FROM freshness.ciphertext_heads "
                                  "WHERE principal=? AND kind=?", (principal, kind)).fetchone()
            if expected != (generation, hashlib.sha256(payload).digest()):
                raise StoreRejected()
        return generation, payload

    def read_ciphertext(self, principal: str, kind: StoreKind) -> tuple[int, bytes]:
        if kind not in ("recovery", "wraps"):
            raise StoreRejected()
        with self._transaction(write=False, ciphertext=True) as db:
            return self._ciphertext_snapshot(db, principal, kind)

    def write_verified_ciphertext(self, principal: str, kind: StoreKind, payload: bytes, *,
                                  generation: int, head: int, authority_revision: int) -> None:
        if (kind not in ("recovery", "wraps") or not isinstance(payload, bytes)
                or type(generation) is not int or not 0 <= generation < MAX_GENERATION):
            raise StoreRejected()
        with self._transaction(write=True, ciphertext=True) as db:
            if self.freshness_path is not None:
                self._ciphertext_snapshot(db, principal, kind)
            if authority_revision != self._authority_revision(db):
                raise HistoryConflict("authority changed before ciphertext commit")
            self._observe_floor(db, principal, head)
            if generation == 0:
                updated = db.execute("INSERT INTO history_ciphertext VALUES (?, ?, 1, ?) "
                                     "ON CONFLICT(principal, kind) DO NOTHING", (principal, kind, payload))
            else:
                updated = db.execute("UPDATE history_ciphertext SET generation=generation+1, payload=? "
                                     "WHERE principal=? AND kind=? AND generation=?",
                                     (payload, principal, kind, generation))
            if updated.rowcount != 1:
                raise StoreRejected()
            if self.freshness_path is not None:
                db.execute("UPDATE freshness.ciphertext_heads SET generation=?, digest=? "
                           "WHERE principal=? AND kind=?",
                           (generation + 1, hashlib.sha256(payload).digest(), principal, kind))
