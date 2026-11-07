from concurrent.futures import ThreadPoolExecutor

import pytest

from acl_service.domain.history_store import HistoryConflict, HistorySnapshot
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
