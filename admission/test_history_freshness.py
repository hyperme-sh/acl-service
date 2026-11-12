"""Clock and commit-boundary unit tests with a mocked signature verifier."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from history_admission import AdmissionRejected, HistoryAdmission


class HistoryFreshnessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = SqliteHistoryStore(Path(directory.name) / "history.db")
        self.store.enroll("synthetic", b"{}")
        self.now = 100
        self.adapter = HistoryAdmission(self.store, grant_for=lambda _: None,
                                        trust_at=lambda _: {}, clock=lambda: self.now)
        self.head = {"sequence": 0, "currentKey": "synthetic-key", "currentEpub": "synthetic-epub"}
        self.adapter._run_verifier = lambda *args, **kwargs: json.dumps(self.head).encode()

    def test_stable_observation_and_read(self):
        self.assertEqual(self.adapter.observe_store_head("synthetic"), self.head)
        row = self.adapter.read_store_row("synthetic", "wraps", "wrap")
        self.assertEqual(row, {"generation": 0, "head": self.head, "row": None})

    def test_verifier_crossing_a_second_cannot_publish_a_head(self):
        def verify(*args, **kwargs):
            self.now += 1
            return json.dumps(self.head).encode()
        self.adapter._run_verifier = verify
        with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
            self.adapter.observe_store_head("synthetic")

    def test_floor_observation_crossing_a_second_cannot_publish_a_head(self):
        original = self.store.observe_head
        def observe(*args, **kwargs):
            original(*args, **kwargs)
            self.now += 1
        self.store.observe_head = observe
        with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
            self.adapter.observe_store_head("synthetic")

    def test_ciphertext_read_crossing_a_second_releases_no_row(self):
        original = self.store.read_ciphertext
        def read(*args, **kwargs):
            result = original(*args, **kwargs)
            self.now += 1
            return result
        self.store.read_ciphertext = read
        with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
            self.adapter.read_store_row("synthetic", "wraps", "wrap")

    def test_signed_write_verification_crossing_a_second_never_commits(self):
        def verify(*args, **kwargs):
            self.now += 1
            return SimpleNamespace(returncode=0, stdout=b'{"wrap":{}}')
        with patch("history_admission.subprocess.run", side_effect=verify):
            with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
                self.adapter.apply_store_operation("synthetic", "wraps", {})
        self.assertEqual(self.store.read_ciphertext("synthetic", "wraps"), (0, b""))

    def test_write_waiting_for_storage_lock_rechecks_inside_transaction(self):
        original = self.store.write_verified_ciphertext
        def delayed(*args, **kwargs):
            self.now += 1
            return original(*args, **kwargs)
        self.store.write_verified_ciphertext = delayed
        with patch("history_admission.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b'{"wrap":{}}')):
            with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
                self.adapter.apply_store_operation("synthetic", "wraps", {})
        self.assertEqual(self.store.read_ciphertext("synthetic", "wraps"), (0, b""))

    def test_expiry_before_commit_rolls_back_the_staged_ciphertext(self):
        revision, _ = self.store.read_authority()
        checks = 0
        def guard():
            nonlocal checks
            checks += 1
            if checks == 2:
                raise AdmissionRejected("history evaluation expired")
        with self.assertRaisesRegex(AdmissionRejected, "evaluation expired"):
            self.store.write_verified_ciphertext("synthetic", "wraps", b'{"wrap":{}}',
                generation=0, head=0, authority_revision=revision, before_commit=guard)
        self.assertEqual(checks, 2)
        self.assertEqual(self.store.read_ciphertext("synthetic", "wraps"), (0, b""))

    def test_stable_write_keeps_existing_generation_contract(self):
        with patch("history_admission.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b'{"wrap":{}}')):
            self.assertEqual(self.adapter.apply_store_operation("synthetic", "wraps", {}), 1)
        self.assertEqual(self.store.read_ciphertext("synthetic", "wraps"), (1, b'{"wrap":{}}'))


if __name__ == "__main__":
    unittest.main()
