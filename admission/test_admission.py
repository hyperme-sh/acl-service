import json
import tempfile
import unittest
from pathlib import Path

from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from history_admission import AdmissionRejected, EnrollmentGrant, HistoryAdmission


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(Path(__file__).with_name("fixture.json").read_bytes())
        f = self.fixture
        self.principal = f["genesis"]
        self.now = f["now"]
        self.grant = EnrollmentGrant(self.principal, "qualification", "one-use-grant", self.now + 60)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = SqliteHistoryStore(Path(directory.name) / "history.db")
        self.adapter = HistoryAdmission(
            self.store, grant_for=lambda _: self.grant, clock=lambda: self.now,
            trust_at=lambda _: {k: f[k] for k in ("policy", "jwks", "pinnedIss")},
        )

    def enroll(self):
        self.adapter.enroll(self.principal, json.dumps(self.fixture["binding"]).encode(),
                            self.fixture["signature"])

    def test_signed_enrollment_and_wallet_admission(self):
        self.enroll()
        wallet = self.fixture["wallet"]
        for invalid in (dict(wallet, keySig="bad"), dict(wallet, principal="another"),
                        dict(wallet, seq=999), dict(wallet, attest="bad")):
            with self.assertRaises(AdmissionRejected):
                self.adapter.admit(self.principal, json.dumps(invalid).encode())
        raw = json.dumps(wallet).encode()
        self.adapter.admit(self.principal, raw)
        with self.assertRaises(AdmissionRejected):
            self.adapter.admit(self.principal, raw)
        self.assertEqual(self.store.read(self.principal).entries, (raw,))

    def test_signed_grant_binding_and_expiry(self):
        original = self.grant
        self.grant = EnrollmentGrant(self.principal, "other", original.nonce, original.expires_at)
        with self.assertRaises(AdmissionRejected):
            self.enroll()
        self.grant = original
        self.now = original.expires_at
        with self.assertRaises(AdmissionRejected):
            self.enroll()
        self.assertIsNone(self.store.read(self.principal))

    def test_witnessed_revocations_and_oidc(self):
        self.enroll()
        for name in ("wallet", "oidc", "revoke"):
            self.adapter.admit(self.principal, json.dumps(self.fixture[name]).encode())
        with self.assertRaises(AdmissionRejected):
            self.adapter.admit(self.principal, json.dumps(self.fixture["offline-current-key-revoke"]).encode())
        self.assertEqual(self.store.read(self.principal).revision, 3)
