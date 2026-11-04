import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acl_service.infrastructure.witness_signer import (
    MAX_INTEGER, P256_ORDER, WitnessKey, WitnessRejected, WitnessSigner, public_jwks,
)


def key(kid="test-key", start=1000, end=2000, scalar=7):
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    return WitnessKey(kid, start, end, private.public_key()), private


def decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def claims():
    jwk = key()[0].jwk()
    return {"typ": "sociacl-acl-attest-v1", "principal": jwk["x"] + "." + jwk["y"],
            "recordId": hashlib.sha256(b"witness publisher contract").hexdigest()}


def test_compact_es256_signature_binds_claims_and_server_timestamps():
    public, private = key()
    token = WitnessSigner(public, private, lambda: 1000).sign_verified(claims(), issued_at=1000)
    header, payload, signature = token.split(".")
    assert json.loads(decode(header)) == {"alg": "ES256", "kid": "test-key", "typ": "JWT"}
    assert json.loads(decode(payload)) == {**claims(), "iat": 1000, "exp": 1900}
    raw = decode(signature)
    assert len(raw) == 64
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    assert 0 < s <= P256_ORDER // 2
    public.public_key.verify(utils.encode_dss_signature(r, s), (header + "." + payload).encode(), ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("now,issued,accepted", [
    (999, 999, False), (1000, 1000, True), (1999, 1999, True),
    (2000, 1999, False), (2001, 1999, False),  # no retired-key backdating
    (1000, 999, False), (1000, 1001, False),
    (1500, 1200, True), (1500, 1199, False),
    (True, 1000, False), (1000, True, False),
    (1000.0, 1000, False), (1000, 1000.0, False),
    (MAX_INTEGER + 1, 1000, False), (1000, -1, False),
])
def test_issuance_and_clock_boundaries(now, issued, accepted):
    public, private = key()
    signer = WitnessSigner(public, private, lambda: now)
    if accepted:
        signer.sign_verified(claims(), issued_at=issued)
    else:
        with pytest.raises(WitnessRejected):
            signer.sign_verified(claims(), issued_at=issued)


@pytest.mark.parametrize("lifetime", [0, 901, -1, True, 1.5, MAX_INTEGER + 1])
def test_invalid_lifetime_rejected(lifetime):
    public, private = key()
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: 1000).sign_verified(claims(), issued_at=1000, lifetime=lifetime)


def test_expired_request_and_timestamp_overflow_rejected():
    public, private = key()
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: 1001).sign_verified(claims(), issued_at=1000, lifetime=1)
    public, private = key(start=MAX_INTEGER - 10, end=MAX_INTEGER)
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: MAX_INTEGER - 1).sign_verified(claims(), issued_at=MAX_INTEGER - 1)


@pytest.mark.parametrize("finish", [999, 2000, 2001, True])
def test_slow_signing_and_clock_rollback_do_not_return_a_token(finish):
    public, private = key()
    clock = iter([1999, finish])
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: next(clock)).sign_verified(claims(), issued_at=1999)


@pytest.mark.parametrize("start,end", [(0, 0), (2, 1), (-1, 2), (True, 2), (0, False), (1.0, 2), (0, MAX_INTEGER + 1)])
def test_malformed_windows_rejected(start, end):
    with pytest.raises(WitnessRejected):
        key(start=start, end=end)


def test_publication_preserves_retired_keys_and_returns_no_private_material():
    old, _ = key()
    new, _ = key("next-key", 2000, 3000, scalar=8)
    published = public_jwks([old, new])
    assert published == {"keys": [old.jwk(), new.jwk()]}
    assert all(set(k) == {"kid", "kty", "crv", "alg", "use", "key_ops", "x", "y", "notBefore", "notAfter"} for k in published["keys"])
    published["keys"][0]["notAfter"] = 3000
    published["keys"][0]["key_ops"].append("sign")
    assert public_jwks([old, new])["keys"][0] == old.jwk()


def test_duplicate_ids_and_reused_key_material_rejected():
    old, _ = key()
    for new in [key("test-key", 2000, 3000, scalar=8)[0], key("new-id", 2000, 3000)[0]]:
        with pytest.raises(WitnessRejected):
            public_jwks([old, new])


def test_wrong_curve_or_mismatched_private_key_rejected():
    public, _ = key()
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, key(scalar=8)[1])
    with pytest.raises(WitnessRejected):
        WitnessKey("wrong-curve", 1000, 2000, ec.generate_private_key(ec.SECP384R1()).public_key())


@pytest.mark.parametrize("extra", [{"iat": 1000}, {"exp": 1900}, {"number": float("nan")}, {"value": object()}])
def test_claims_cannot_override_timestamps_or_encode_invalid_json(extra):
    public, private = key()
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: 1000).sign_verified({**claims(), **extra}, issued_at=1000)


def test_oversize_token_and_expiry_during_signing_rejected():
    public, private = key()
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: 1000).sign_verified({"value": "x" * 16384}, issued_at=1000)
    clock = iter([1000, 1001])
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: next(clock)).sign_verified(claims(), issued_at=1000, lifetime=1)


def test_committed_interop_sample_matches_publisher_contract():
    from pathlib import Path
    fixture = json.loads((Path(__file__).parent / "fixtures/sociacl-witness.json").read_text())
    public, private = key(fixture["jwks"]["keys"][0]["kid"], end=1001)
    assert fixture["jwks"] == public_jwks([public])
    for token in [fixture["input"]["jws"], WitnessSigner(public, private, lambda: 1000).sign_verified(claims(), issued_at=1000)]:
        header, payload, signature = token.split(".")
        assert json.loads(decode(payload)) == fixture["canonical"]
        raw = decode(signature)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        assert 0 < s <= P256_ORDER // 2
        public.public_key.verify(utils.encode_dss_signature(r, s), (header + "." + payload).encode(), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(WitnessRejected):
        WitnessSigner(public, private, lambda: 1001).sign_verified(claims(), issued_at=1000)
