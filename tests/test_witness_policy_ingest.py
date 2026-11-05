import base64
import json
import time
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_signer import WitnessRejected, P256_ORDER
from acl_service.infrastructure.witness_policy_repo import read_policy
from acl_service import witness_policy_cli as cli
from test_witness_policy_repo import engine, key  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401

ROOT_KEY = ec.derive_private_key(17, ec.SECP256R1())
AUDIENCE = "panopticon-test"


def document():
    now = int(time.time())
    return {"type": "sociacl-witness-policy-v1", "audience": AUDIENCE,
            "revision": 1, "issuedAt": now - 1, "expiresAt": now + 60,
            "jwks": {"keys": [key()[0].jwk()]}}


def sign(payload, root=ROOT_KEY):
    r, s = utils.decode_dss_signature(root.sign(ingest.DOMAIN + payload, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + min(s, P256_ORDER - s).to_bytes(32, "big")


def bundle(value=None):
    payload = json.dumps(document() if value is None else value).encode()
    return payload, sign(payload)


def verify(payload, signature, root=None, audience=AUDIENCE):
    return ingest.verify_policy(payload, signature, root or ROOT_KEY.public_key(), audience)


def test_verified_bundle_binds_all_policy_fields():
    d = document()
    payload, signature = bundle(d)
    verified = verify(payload, signature)
    assert verified.revision == d["revision"]
    assert verified.keys[0].jwk() == d["jwks"]["keys"][0]
    assert verified.expires_at == d["expiresAt"]
    for field in ["revision", "audience", "issuedAt", "expiresAt", "jwks"]:
        changed = deepcopy(d)
        changed[field] = None
        with pytest.raises(WitnessRejected):
            verify(json.dumps(changed).encode(), signature)
    with pytest.raises(WitnessRejected):
        verify(payload + b" ", signature)
    with pytest.raises(WitnessRejected):
        verify(payload, signature, audience="another-deployment")
    with pytest.raises(WitnessRejected):
        verify(payload, signature, root=ec.derive_private_key(18, ec.SECP256R1()).public_key())


@pytest.mark.parametrize("field,value", [
    ("revision", 0), ("revision", True), ("revision", 1.5), ("revision", 9007199254740992),
    ("issuedAt", True), ("expiresAt", False), ("type", "other"), ("jwks", []),
])
def test_invalid_signed_fields_rejected(field, value):
    d = document(); d[field] = value
    with pytest.raises(WitnessRejected):
        verify(*bundle(d))


@pytest.mark.parametrize("start,end,accepted", [
    (1000, 1001, True), (999, 1000, False), (1001, 1002, False),
    (1000, 1000, False), (1000, 87400, True), (1000, 87401, False),
])
def test_transport_validity_boundaries(monkeypatch, start, end, accepted):
    d = document(); d.update(issuedAt=start, expiresAt=end)
    monkeypatch.setattr(ingest.time, "time", lambda: 1000)
    if accepted:
        verify(*bundle(d))
    else:
        with pytest.raises(WitnessRejected):
            verify(*bundle(d))


@pytest.mark.parametrize("mutation", ["private", "unknown", "signing", "wrong-curve", "duplicate-id", "duplicate-key", "noncanonical-x", "root-as-witness"])
def test_strict_public_key_registry(mutation):
    d = document(); jwk = d["jwks"]["keys"][0]
    if mutation == "private": jwk["d"] = "secret"
    elif mutation == "unknown": jwk["extra"] = "ignored?"
    elif mutation == "signing": jwk["key_ops"] = ["sign", "verify"]
    elif mutation == "wrong-curve": jwk["crv"] = "P-384"
    elif mutation == "duplicate-id": d["jwks"]["keys"].append(deepcopy(jwk))
    elif mutation == "duplicate-key": d["jwks"]["keys"].append({**jwk, "kid": "new-name"})
    elif mutation == "noncanonical-x": jwk["x"] += "="
    else:
        from acl_service.infrastructure.witness_signer import WitnessKey
        d["jwks"]["keys"] = [WitnessKey("root", 1, 2000, ROOT_KEY.public_key()).jwk()]
    with pytest.raises(WitnessRejected):
        verify(*bundle(d))


def test_duplicate_json_members_and_oversize_rejected():
    payload, _ = bundle()
    for raw in [payload[:-1] + b', "revision": 1}', b'"' + b'x' * ingest.MAX_POLICY_BYTES + b'"', b'\xff']:
        with pytest.raises(WitnessRejected):
            verify(raw, sign(raw))


def test_signature_is_compact_low_s_and_domain_bound():
    payload, signature = bundle()
    high_s = signature[:32] + (P256_ORDER - int.from_bytes(signature[32:], "big")).to_bytes(32, "big")
    der = ROOT_KEY.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    wrong_domain = r.to_bytes(32, "big") + min(s, P256_ORDER-s).to_bytes(32, "big")
    for invalid in [b"", signature[:-1], signature + b"x", b"\0" * 64, high_s, wrong_domain]:
        with pytest.raises(WitnessRejected):
            verify(payload, invalid)


def test_authenticated_install_still_enforces_durable_revision(engine):
    d = document(); payload, signature = bundle(d)
    installed = ingest.install_signed_policy(engine, payload, signature, ROOT_KEY.public_key(), AUDIENCE)
    assert installed.revision == 1
    d["revision"] = 2; d["jwks"] = {"keys": []}
    newer = bundle(d)
    ingest.install_signed_policy(engine, *newer, ROOT_KEY.public_key(), AUDIENCE)
    with pytest.raises(WitnessRejected):
        ingest.install_signed_policy(engine, payload, signature, ROOT_KEY.public_key(), AUDIENCE)
    assert read_policy(engine).revision == 2
    assert read_policy(engine).jwks == {"keys": []}


def test_expired_authorization_under_lock_rolls_back(engine, monkeypatch):
    d = document(); d.update(issuedAt=999, expiresAt=1001)
    payload, signature = bundle(d)
    samples = iter([1000, 1001])
    monkeypatch.setattr(ingest.time, "time", lambda: next(samples))
    with pytest.raises(WitnessRejected):
        ingest.install_signed_policy(engine, payload, signature, ROOT_KEY.public_key(), AUDIENCE)
    assert read_policy(engine) is None


def files(tmp_path, payload, signature):
    policy, sig, root = (tmp_path / name for name in ["policy.json", "policy.sig", "root.pem"])
    policy.write_bytes(payload); sig.write_bytes(signature)
    root.write_bytes(ROOT_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return ["--policy", str(policy), "--signature", str(sig), "--root-key", str(root), "--audience", AUDIENCE]


def test_cli_check_and_invalid_input_never_connect(tmp_path, monkeypatch, capsys):
    def no_database(*args, **kwargs):
        pytest.fail("verification must happen before database connection")
    monkeypatch.setattr(cli, "create_engine", no_database)
    payload, signature = bundle()
    assert cli.main(files(tmp_path, payload, signature) + ["--check"]) == 0
    assert '"installed": false' in capsys.readouterr().out
    assert cli.main(files(tmp_path, payload, b"bad")) == 1
    assert capsys.readouterr().out == "witness policy rejected\n"


def test_cli_install_reports_only_committed_revision(engine, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", engine.url.render_as_string(hide_password=False))
    payload, signature = bundle()
    assert cli.main(files(tmp_path, payload, signature)) == 0
    assert json.loads(capsys.readouterr().out) == {"installedRevision": 1, "installed": True}
    assert read_policy(engine).revision == 1
