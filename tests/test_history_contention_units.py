"""Transaction failure units with fake connections; no SQLite I/O."""
import sqlite3
import unittest
from unittest.mock import Mock, MagicMock
from acl_service.domain.history_store import HistoryConflict
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore


class ContentionTests(unittest.TestCase):
    def test_busy_and_locked_roll_back_close_and_require_a_new_fence(self):
        for code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_BUSY | (2 << 8)):
            for on_commit in (False, True):
                with self.subTest(code=code, on_commit=on_commit):
                    error = sqlite3.OperationalError('private database path')
                    error.sqlite_errorcode = code
                    connection = MagicMock()
                    if on_commit: connection.__exit__.side_effect = error
                    else: connection.execute.side_effect = error
                    store = object.__new__(SqliteHistoryStore)
                    store.require_authority_checkpoint = False; store.freshness_path = None
                    store._connect = Mock(return_value=connection)
                    with self.assertRaisesRegex(HistoryConflict, '^store contention; refresh required$'):
                        with store._transaction(write=True): pass
                    store._connect.assert_called_once()
                    connection.__exit__.assert_called_once()
                    connection.close.assert_called_once()

    def test_unrelated_database_failures_are_not_conflicts(self):
        error = sqlite3.OperationalError('invalid schema'); error.sqlite_errorcode = sqlite3.SQLITE_ERROR
        connection = MagicMock(); connection.execute.side_effect = error
        store = object.__new__(SqliteHistoryStore)
        store.require_authority_checkpoint = False; store.freshness_path = None
        store._connect = Mock(return_value=connection)
        with self.assertRaises(sqlite3.OperationalError):
            with store._transaction(write=False): pass
        connection.close.assert_called_once()


if __name__ == '__main__': unittest.main()
