from concurrent.futures import ThreadPoolExecutor

import pytest

from acl_service.domain.history_store import HistoryConflict, HistorySnapshot
from acl_service.domain.keyring_store import StoreRejected
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore


def test_exclusive_enrollment_and_reopen(tmp_path):
    path = tmp_path / "ledger.db"
    store = SqliteHistoryStore(path)
    assert store.read("a") is None
    with pytest.raises(HistoryConflict):
        store.append("a", 0, b"orphan")
    store.enroll("a", b"genesis")
    store.enroll("b", b"other")
    with pytest.raises(HistoryConflict):
        store.enroll("a", b"replacement")
    store.append("a", 0, b"one")
    store.append("a", 1, b"two")
    reopened = SqliteHistoryStore(path)
    assert reopened.read("a") == HistorySnapshot("a", b"genesis", (b"one", b"two"))
    assert reopened.read("b") == HistorySnapshot("b", b"other", ())


def test_competing_admissions(tmp_path):
    store = SqliteHistoryStore(tmp_path / "ledger.db")
    store.enroll("a", b"genesis")

    def compete(entry):
        try:
            store.append("a", 0, entry)
        except HistoryConflict:
            return None
        return entry

    with ThreadPoolExecutor(max_workers=2) as executor:
        winners = tuple(e for e in executor.map(compete, (b"x", b"y")) if e)
    assert len(winners) == 1
    assert store.read("a").entries == winners


@pytest.mark.parametrize("kind", ["recovery", "wraps"])
@pytest.mark.parametrize("rejected_generation", [0, 2])
def test_rejected_generation_rolls_back_shared_floor(tmp_path, kind, rejected_generation):
    path = tmp_path / "ledger.db"
    store = SqliteHistoryStore(path)
    store.enroll("a", b"genesis")
    revision, _ = store.read_authority()
    store.write_verified_ciphertext("a", kind, b"first", generation=0, head=0,
                                    authority_revision=revision)
    with pytest.raises(StoreRejected):
        store.write_verified_ciphertext("a", kind, b"rejected", generation=rejected_generation,
                                        head=1, authority_revision=revision)

    reopened = SqliteHistoryStore(path)
    assert reopened.read_ciphertext("a", kind) == (1, b"first")
    other_kind = "recovery" if kind == "wraps" else "wraps"
    reopened.write_verified_ciphertext("a", other_kind, b"other", generation=0, head=0,
                                       authority_revision=revision)


@pytest.mark.parametrize("kind", ["recovery", "wraps"])
def test_independent_ciphertext_head_survives_ledger_restore(tmp_path, kind):
    import hashlib
    import shutil
    import sqlite3
    from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

    path = tmp_path / "ledger"
    store = SqliteHistoryStore(path)
    store.enroll("a", b"genesis")
    snapshot = tmp_path / "snapshot"
    shutil.copyfile(path, snapshot)
    anchor = tmp_path / "freshness"
    initialize(snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest(), anchor)
    with pytest.raises(FileExistsError):
        initialize(snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest(), anchor)
    writer = SqliteHistoryStore(path, freshness_path=anchor)
    revision, _ = writer.read_authority()
    writer.write_verified_ciphertext("a", kind, b"one", generation=0, head=0, authority_revision=revision)
    assert writer.read_ciphertext("a", kind) == (1, b"one")
    with sqlite3.connect(anchor) as db:
        db.execute("CREATE TRIGGER reject_update BEFORE UPDATE ON ciphertext_heads "
                   "BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        writer.write_verified_ciphertext("a", kind, b"two", generation=1, head=1, authority_revision=revision)
    assert writer.read_ciphertext("a", kind) == (1, b"one")
    writer.observe_head("a", 0, authority_revision=revision)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE history_ciphertext SET payload=?", (b"divergent",))
    with pytest.raises(StoreRejected):
        writer.read_ciphertext("a", kind)
    shutil.copyfile(snapshot, path)
    with pytest.raises(StoreRejected):
        writer.write_verified_ciphertext("a", kind, b"replay", generation=0, head=0, authority_revision=revision)


def test_authority_checkpoint_rejects_rollback_and_peer_divergence(tmp_path):
    import hashlib
    import shutil
    import sqlite3
    from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

    path, snapshot, anchor = (tmp_path / name for name in ("ledger", "snapshot", "anchor"))
    original = SqliteHistoryStore(path)
    original.enroll("account", b"genesis")
    shutil.copyfile(path, snapshot)
    initialize(snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest(), anchor)
    store = SqliteHistoryStore(path, freshness_path=anchor, require_authority_checkpoint=True)
    store.enroll("peer", b"peer-genesis")
    store.append("peer", 0, b"record", verified_rotation=1)
    revision, _ = store.read_authority()
    store.write_verified_ciphertext("peer", "wraps", b"payload", generation=0, head=1, authority_revision=revision)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE history_entries SET entry=? WHERE principal='peer'", (b"other",))
    with pytest.raises(StoreRejected):
        store.read("account")
    with pytest.raises(StoreRejected):
        store.write_verified_ciphertext("account", "recovery", b"data", generation=0, head=0, authority_revision=revision)
    shutil.copyfile(snapshot, path)
    with pytest.raises(StoreRejected):
        store.enroll("third", b"genesis")
    with pytest.raises(StoreRejected):
        store.read_authority()


def test_checkpoint_update_failure_rolls_back_admission(tmp_path):
    import hashlib
    import sqlite3
    from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

    path, anchor = tmp_path / "ledger", tmp_path / "anchor"
    SqliteHistoryStore(path).enroll("a", b"genesis")
    initialize(path, hashlib.sha256(path.read_bytes()).hexdigest(), anchor)
    store = SqliteHistoryStore(path, freshness_path=anchor, require_authority_checkpoint=True)
    with sqlite3.connect(anchor) as db:
        db.execute("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON authority_checkpoint "
                   "BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.append("a", 0, b"rotation", verified_rotation=1)
    assert store.read("a").entries == ()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM history_head_floors").fetchall() == []


@pytest.mark.parametrize("kind", ["recovery", "wraps"])
def test_readback_fences_peer_authority_changes(tmp_path, kind):
    store = SqliteHistoryStore(tmp_path / "ledger.db")
    store.enroll("a", b"genesis")
    revision, _ = store.read_authority()
    store.write_verified_ciphertext("a", kind, b"row", generation=0, head=0,
                                    authority_revision=revision)
    assert store.read_ciphertext("a", kind, authority_revision=revision) == (1, b"row")
    store.enroll("peer", b"peer genesis")
    with pytest.raises(HistoryConflict):
        store.read_ciphertext("a", kind, authority_revision=revision)
