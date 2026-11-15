"""Mock-only journal constructor transaction ownership units."""
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from acl_service.infrastructure.group_media_journal import GroupMediaJournal
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore

class GroupTransactionTests(TestCase):
    def setUp(self):
        self.store=object.__new__(PostgresHistoryStore)
        self.store.history_schema='history';self.store.checkpoint_schema='checkpoint'
        self.db=SimpleNamespace(origin=self.store,history='history',checkpoint='checkpoint',execute=Mock())
        self.store._transaction=Mock(side_effect=AssertionError('must reuse active transaction'))

    def test_supplied_owned_transaction_checks_tables_without_nesting(self):
        journal=GroupMediaJournal(self.store,transaction=self.db)
        self.assertIs(journal.store,self.store);self.assertEqual(self.db.execute.call_count,2)
        self.store._transaction.assert_not_called()

    def test_foreign_transaction_never_reaches_sql(self):
        self.db.origin=object()
        with self.assertRaises(ValueError):GroupMediaJournal(self.store,transaction=self.db)
        self.db.execute.assert_not_called()

    def test_normal_constructor_still_opens_one_read_transaction(self):
        @contextmanager
        def transaction(*,write):self.assertFalse(write);yield self.db
        self.store._transaction=Mock(side_effect=transaction)
        GroupMediaJournal(self.store)
        self.store._transaction.assert_called_once_with(write=False);self.assertEqual(self.db.execute.call_count,2)
