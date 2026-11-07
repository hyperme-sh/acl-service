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

    def test_rotation_and_durable_fork(self):
        from history_admission import FORK_PREFIX, RotationFork

        self.enroll()
        def admit(record):
            self.adapter.admit(self.principal, json.dumps(record).encode())

        admit(self.fixture["oidc"])
        rotation = self.fixture["probe-v3-oidc"]
        for invalid in (dict(rotation, seq=999), dict(rotation, nextSig="invalid"),
                        self.fixture["rotate-v4-wallet"]):
            with self.assertRaises(AdmissionRejected):
                admit(invalid)
        self.assertEqual(self.store.read(self.principal).revision, 1)
        admit(rotation)
        with self.assertRaises(AdmissionRejected):
            admit(rotation)

        sibling = self.fixture["oidc-rotate"]
        with self.assertRaises(AdmissionRejected):
            admit(dict(sibling, attest="invalid"))
        self.assertEqual(self.store.read(self.principal).revision, 2)
        # A concurrent admission commits between sibling verification and CAS.
        original_append = self.store.append
        def racing_append(principal, revision, raw):
            self.store.append = original_append
            admit(self.fixture["oidc-after-rotation"])
            original_append(principal, revision, raw)
        self.store.append = racing_append
        with self.assertRaises(RotationFork):
            admit(sibling)
        self.adapter.store = SqliteHistoryStore(self.store.path)
        with self.assertRaises(RotationFork):
            admit(rotation)
        snapshot = self.store.read(self.principal)
        self.assertEqual(snapshot.revision, 4)
        self.assertEqual(snapshot.entries[-1], FORK_PREFIX + json.dumps(sibling).encode())

    def test_wallet_rotation(self):
        self.enroll()
        for name in ("wallet", "rotate-v4-wallet"):
            self.adapter.admit(self.principal, json.dumps(self.fixture[name]).encode())
        self.assertEqual(self.store.read(self.principal).revision, 2)

    def test_new_wallet_owner_wins_during_admission(self):
        self.enroll()
        self.adapter.admit(self.principal, json.dumps(self.fixture["wallet"]).encode())
        peer = self.enroll_peer()
        original_append = self.store.append

        def race(principal, revision, raw, **fence):
            self.store.append = original_append
            self.adapter.admit(peer, json.dumps(self.fixture["peerWalletAfterRotation"]).encode())
            original_append(principal, revision, raw, **fence)

        self.store.append = race
        with self.assertRaises(AdmissionRejected):
            self.adapter.admit(self.principal, json.dumps(self.fixture["rotate-v4-wallet"]).encode())
        self.assertEqual(self.store.read(self.principal).revision, 1)
        self.assertEqual(self.store.read(peer).revision, 1)

    def enroll_peer(self):
        peer = self.fixture["peerBinding"]["principal"]
        self.grant = EnrollmentGrant(peer, "qualification", "peer-grant", self.now + 60)
        self.adapter.enroll(peer, json.dumps(self.fixture["peerBinding"]).encode(),
                            self.fixture["peerSignature"])
        return peer

    def test_equal_time_claims_deny_rotation(self):
        self.enroll()
        peer = self.enroll_peer()
        self.adapter.admit(peer, json.dumps(self.fixture["peerWalletTie"]).encode())
        self.adapter.admit(self.principal, json.dumps(self.fixture["wallet"]).encode())
        with self.assertRaises(AdmissionRejected):
            self.adapter.admit(self.principal, json.dumps(self.fixture["rotate-v4-wallet"]).encode())
        self.assertEqual(self.store.read(self.principal).revision, 1)
