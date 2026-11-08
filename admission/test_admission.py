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
        with self.assertRaises(RotationFork):
            self.adapter.observe_store_head(self.principal)
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

    def test_observed_head_uses_verified_sequence_and_shared_floor(self):
        from acl_service.domain.keyring_store import StoreRejected

        self.enroll()
        for name in ("wallet", "rotate-v4-wallet"):
            self.adapter.admit(self.principal, json.dumps(self.fixture[name]).encode())
        revision, _ = self.store.read_authority()
        with self.assertRaises(StoreRejected):
            self.store.observe_head(self.principal, 0, authority_revision=revision)
        snapshot = self.store.read(self.principal)
        # Simulate an invalid rotation in imported storage.
        forged = dict(self.fixture["rotate-v4-wallet"], seq=999)
        self.store.append(self.principal, snapshot.revision, json.dumps(forged).encode())
        result = self.adapter.observe_store_head(self.principal)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["currentKey"], self.fixture["rotate-v4-wallet"]["nextKey"])
        self.assertTrue(result["diagnostics"])
        reopened = SqliteHistoryStore(self.store.path)
        revision, _ = reopened.read_authority()
        with self.assertRaises(StoreRejected):
            reopened.observe_head(self.principal, 0, authority_revision=revision)

    def test_observation_rejects_concurrent_authority_write(self):
        from acl_service.domain.history_store import HistoryConflict

        self.enroll()
        original = self.store.observe_head

        def race(principal, head, *, authority_revision):
            self.enroll_peer()
            original(principal, head, authority_revision=authority_revision)

        self.store.observe_head = race
        with self.assertRaises(HistoryConflict):
            self.adapter.observe_store_head(self.principal)
        self.store.observe_head = original
        self.assertEqual(self.adapter.observe_store_head(self.principal)["sequence"], 0)

    def store_operations(self):
        return json.loads(Path(__file__).with_name("store-fixture.json").read_bytes())

    def test_signed_recovery_and_wrap_lifecycle(self):
        self.enroll()
        ops = self.store_operations()
        def apply(kind, name):
            return self.adapter.apply_store_operation(self.principal, kind, ops[name])

        self.assertEqual(apply("recovery", "current"), 1)
        self.assertEqual(apply("wraps", "wrap"), 1)
        self.assertEqual(apply("recovery", "pending"), 2)
        target = ops["wrap"]["row"]["wrapId"]
        reread = self.adapter.read_store_row(self.principal, "wraps", target)
        self.assertEqual((reread["generation"], reread["row"]), (1, ops["wrap"]["row"]))
        self.assertEqual(apply("wraps", "deleteWrap"), 2)
        reread = self.adapter.read_store_row(self.principal, "wraps", target)
        self.assertEqual((reread["generation"], reread["row"]), (2, None))
        with self.assertRaises(AdmissionRejected):
            apply("wraps", "wrap")
        with self.assertRaises(AdmissionRejected):
            apply("recovery", "commit")
        for name in ("wallet", "rotate-v4-wallet"):
            self.adapter.admit(self.principal, json.dumps(self.fixture[name]).encode())
        self.assertEqual(apply("recovery", "commit"), 3)
        self.adapter.store = SqliteHistoryStore(self.store.path)
        generation, payload = self.adapter.store.read_ciphertext(self.principal, "recovery")
        self.assertEqual(generation, 3)
        self.assertEqual(json.loads(payload), {"current": ops["pending"]["row"]})
        self.assertEqual(apply("recovery", "deleteCommitted"), 4)
        self.assertEqual(self.store.read_ciphertext(self.principal, "recovery"), (4, b"{}"))

    def test_tampering_and_wrong_store_leave_ciphertext_untouched(self):
        self.enroll()
        ops = self.store_operations()
        for kind, name in (("wraps", "wrap"), ("recovery", "current")):
            op = ops[name]
            corrupted = dict(op["row"], epub=self.principal)
            for invalid in (dict(op, row=corrupted), dict(op, signature="00"*64),
                            dict(op, generation=0), ops["wrap" if kind == "recovery" else "current"]):
                with self.assertRaises(AdmissionRejected):
                    self.adapter.apply_store_operation(self.principal, kind, invalid)
            self.assertEqual(self.store.read_ciphertext(self.principal, kind), (0, b""))

    def test_authority_change_after_signature_verification_aborts_write(self):
        from acl_service.domain.history_store import HistoryConflict

        self.enroll()
        original = self.store.write_verified_ciphertext
        def race(*args, **kwargs):
            self.enroll_peer()
            original(*args, **kwargs)
        self.store.write_verified_ciphertext = race
        with self.assertRaises(HistoryConflict):
            self.adapter.apply_store_operation(self.principal, "wraps", self.store_operations()["wrap"])
        self.assertEqual(self.store.read_ciphertext(self.principal, "wraps"), (0, b""))

    def test_signed_genesis_wrap_deletion_stays_forbidden(self):
        self.enroll()
        ops = self.store_operations()
        self.adapter.apply_store_operation(self.principal, "wraps", ops["genesisWrap"])
        before = self.store.read_ciphertext(self.principal, "wraps")
        with self.assertRaises(AdmissionRejected):
            self.adapter.apply_store_operation(self.principal, "wraps", ops["deleteGenesis"])
        self.assertEqual(self.store.read_ciphertext(self.principal, "wraps"), before)

    def test_concurrent_valid_signed_write_commits_once(self):
        from acl_service.domain.keyring_store import StoreRejected

        self.enroll()
        put = self.store_operations()["current"]
        original = self.store.write_verified_ciphertext
        def race(*args, **kwargs):
            self.store.write_verified_ciphertext = original
            self.adapter.apply_store_operation(self.principal, "recovery", put)
            original(*args, **kwargs)
        self.store.write_verified_ciphertext = race
        with self.assertRaises(StoreRejected):
            self.adapter.apply_store_operation(self.principal, "recovery", put)
        generation, payload = self.store.read_ciphertext(self.principal, "recovery")
        self.assertEqual(generation, 1)
        self.assertEqual(json.loads(payload), {"current": put["row"]})

    def test_predecessor_and_current_signer_are_independently_verified(self):
        self.enroll()
        ops = self.store_operations()
        wrap = ops["wrap"]
        self.adapter.apply_store_operation(self.principal, "wraps", wrap)
        before = self.store.read_ciphertext(self.principal, "wraps")
        # Correct key, target, head and generation, but signs an absent predecessor.
        with self.assertRaises(AdmissionRejected):
            self.adapter.apply_store_operation(self.principal, "wraps",
                                               dict(wrap, signature=ops["stalePredecessor"]))
        self.assertEqual(self.store.read_ciphertext(self.principal, "wraps"), before)

        # A different enrolled ledger has the new head and an empty wrap store.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.adapter.store = SqliteHistoryStore(Path(directory.name) / "rotated.db")
        self.enroll()
        for name in ("wallet", "rotate-v4-wallet"):
            self.adapter.admit(self.principal, json.dumps(self.fixture[name]).encode())
        with self.assertRaises(AdmissionRejected):
            self.adapter.apply_store_operation(self.principal, "wraps",
                                               dict(wrap, signature=ops["retiredKey"]))
        self.assertEqual(self.adapter.store.read_ciphertext(self.principal, "wraps"), (0, b""))
