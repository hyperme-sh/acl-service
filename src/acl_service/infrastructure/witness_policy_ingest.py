"""Authenticate offline operator policy bundles before touching durable trust state."""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acl_service.infrastructure.witness_signer import MAX_INTEGER, P256_ORDER, WitnessKey, WitnessRejected, public_jwks
from acl_service.domain.witness_policy_writer import WitnessPolicyWriter

DOMAIN = b"sociacl-witness-policy-v1\n"
MAX_POLICY_BYTES = 262144
MAX_UPDATE_LIFETIME = 86400


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WitnessRejected()
        result[key] = value
    return result


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def _coordinate(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise WitnessRejected()
    raw = base64.urlsafe_b64decode(value + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise WitnessRejected()
    return int.from_bytes(raw, "big")


@dataclass(frozen=True)
class VerifiedPolicy:
    revision: int
    keys: tuple[WitnessKey, ...]
    issued_at: int
    expires_at: int

    def check_current(self):
        now = int(time.time())
        if not self.issued_at <= now < self.expires_at:
            raise WitnessRejected()


def verify_policy(payload: bytes, signature: bytes, root_key, audience: str) -> VerifiedPolicy:
    """Verify exact file bytes with an independently provisioned P-256 root.

    No root discovery, network fetch, algorithm negotiation or client clock input.
    Signature is compact low-S ES256 over DOMAIN followed by the raw UTF-8 file.
    """
    if (not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_POLICY_BYTES
            or not isinstance(signature, bytes) or len(signature) != 64
            or not isinstance(root_key, ec.EllipticCurvePublicKey)
            or not isinstance(root_key.curve, ec.SECP256R1)
            or not isinstance(audience, str) or not audience):
        raise WitnessRejected()
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not 0 < r < P256_ORDER or not 0 < s <= P256_ORDER // 2:
        raise WitnessRejected()
    try:
        root_key.verify(utils.encode_dss_signature(r, s), DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
        if (not isinstance(document, dict)
                or set(document) != {"type", "audience", "revision", "issuedAt", "expiresAt", "jwks"}
                or document["type"] != "sociacl-witness-policy-v1"
                or document["audience"] != audience
                or not _integer(document["revision"]) or document["revision"] == 0
                or not _integer(document["issuedAt"]) or not _integer(document["expiresAt"])
                or not 0 < document["expiresAt"] - document["issuedAt"] <= MAX_UPDATE_LIFETIME):
            raise WitnessRejected()
        keys = _parse_jwks(document["jwks"], root_key)
        verified = VerifiedPolicy(document["revision"], tuple(keys), document["issuedAt"], document["expiresAt"])
        verified.check_current()
        return verified
    except (InvalidSignature, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise WitnessRejected() from None


def _parse_jwks(jwks, root_key) -> tuple[WitnessKey, ...]:
    """Validate public policy/history keys against the independently pinned root."""
    if not isinstance(jwks, dict) or set(jwks) != {"keys"} or not isinstance(jwks["keys"], list):
        raise WitnessRejected()
    keys = []
    for jwk in jwks["keys"]:
        if (not isinstance(jwk, dict)
                or set(jwk) != {"kid", "kty", "crv", "alg", "use", "key_ops", "x", "y", "notBefore", "notAfter"}
                or jwk["kty"] != "EC" or jwk["crv"] != "P-256" or jwk["alg"] != "ES256"
                or jwk["use"] != "sig" or jwk["key_ops"] != ["verify"]):
            raise WitnessRejected()
        public = ec.EllipticCurvePublicNumbers(_coordinate(jwk["x"]), _coordinate(jwk["y"]), ec.SECP256R1()).public_key()
        if public.public_numbers() == root_key.public_numbers():
            raise WitnessRejected()  # Administrative and online witness keys are separate.
        keys.append(WitnessKey(jwk["kid"], jwk["notBefore"], jwk["notAfter"], public))
    public_jwks(keys)  # Reject duplicate identifiers and public key material.
    return tuple(keys)


def install_signed_policy(writer: WitnessPolicyWriter, payload: bytes, signature: bytes, root_key, audience: str):
    verified = verify_policy(payload, signature, root_key, audience)
    # Recheck time inside the serialized write: waiting for another writer cannot outlive
    # the signed update's validity and then silently install it.
    return writer.install_verified(
        verified.revision, verified.keys, check_authorization=verified.check_current,
    )
