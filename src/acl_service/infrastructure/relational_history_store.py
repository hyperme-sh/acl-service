"""Backend-neutral history operations inside a backend-owned transaction."""
from collections.abc import Callable
import hashlib

from acl_service.domain.history_store import HistoryConflict, HistorySnapshot
from acl_service.domain.keyring_store import MAX_GENERATION, StoreKind, StoreRejected


class RelationalHistoryStore:
    """Implementations supply serialized transactions and positional SQL bindings."""

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

    def _ciphertext_snapshot(self, db, principal, kind):
        row = db.execute("SELECT generation, payload FROM main.history_ciphertext "
                         "WHERE principal=? AND kind=?", (principal, kind)).fetchone()
        generation, payload = row if row is not None else (0, b"")
        if self.has_freshness:
            expected = db.execute("SELECT generation, digest FROM freshness.ciphertext_heads "
                                  "WHERE principal=? AND kind=?", (principal, kind)).fetchone()
            if expected != (generation, hashlib.sha256(payload).digest()):
                raise StoreRejected()
        return generation, payload

    def read_ciphertext(self, principal: str, kind: StoreKind, *, authority_revision: int | None = None) -> tuple[int, bytes]:
        if kind not in ("recovery", "wraps"):
            raise StoreRejected()
        with self._transaction(write=False, ciphertext=True) as db:
            if authority_revision is not None and authority_revision != self._authority_revision(db):
                raise HistoryConflict("authority changed before ciphertext read")
            return self._ciphertext_snapshot(db, principal, kind)

    def write_verified_ciphertext(self, principal: str, kind: StoreKind, payload: bytes, *,
                                  generation: int, head: int, authority_revision: int,
                                  before_commit: Callable[[], None] | None = None) -> None:
        if (kind not in ("recovery", "wraps") or not isinstance(payload, bytes)
                or type(generation) is not int or not 0 <= generation < MAX_GENERATION):
            raise StoreRejected()
        with self._transaction(write=True, ciphertext=True, before_commit=before_commit) as db:
            if self.has_freshness:
                self._ciphertext_snapshot(db, principal, kind)
            if authority_revision != self._authority_revision(db):
                raise HistoryConflict("authority changed before ciphertext commit")
            if before_commit is not None:
                before_commit()
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
            if self.has_freshness:
                db.execute("UPDATE freshness.ciphertext_heads SET generation=?, digest=? "
                           "WHERE principal=? AND kind=?",
                           (generation + 1, hashlib.sha256(payload).digest(), principal, kind))
