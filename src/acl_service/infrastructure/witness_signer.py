"""Internal timestamp signer, not an identity verifier or public endpoint.

Only an authenticated adapter may supply verified claims. It must use SociACL
for record signatures, complete/fresh history and present-revocation checks.
Key windows come from trusted operator policy, never request claims or headers.
"""
from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

MAX_INTEGER = 9_007_199_254_740_991
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class WitnessRejected(ValueError):
    def __init__(self) -> None:
        super().__init__("witness-rejected")


def _integer(value: int) -> bool:
    return type(value) is int and 0 <= value <= MAX_INTEGER


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json(value: dict) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True,
                           allow_nan=False).encode("utf-8"))


@dataclass(frozen=True)
class WitnessKey:
    kid: str
    not_before: int
    not_after: int
    public_key: ec.EllipticCurvePublicKey = field(repr=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.kid, str) or not self.kid or len(self.kid) > 128
                or not _integer(self.not_before) or not _integer(self.not_after)
                or self.not_before >= self.not_after
                or not isinstance(self.public_key, ec.EllipticCurvePublicKey)
                or not isinstance(self.public_key.curve, ec.SECP256R1)):
            raise WitnessRejected()

    def jwk(self) -> dict:
        point = self.public_key.public_numbers()
        return {"kid": self.kid, "kty": "EC", "crv": "P-256", "alg": "ES256",
                "use": "sig", "key_ops": ["verify"],
                "x": _b64(point.x.to_bytes(32, "big")),
                "y": _b64(point.y.to_bytes(32, "big")),
                "notBefore": self.not_before, "notAfter": self.not_after}


def public_jwks(keys: Sequence[WitnessKey]) -> dict:
    """Publish fresh copies of all trusted keys, including retired windows.

    A new issuance period requires both a new key and a unique kid. This checks
    one complete policy; durable policy history/anti-rollback remains external.
    """
    kids: set[str] = set()
    points: set[tuple[int, int]] = set()
    result = []
    for key in keys:
        point = key.public_key.public_numbers()
        coordinate = (point.x, point.y)
        if key.kid in kids or coordinate in points:
            raise WitnessRejected()
        kids.add(key.kid)
        points.add(coordinate)
        result.append(key.jwk())
    return {"keys": result}


def _clock() -> int:
    return int(time.time())


@dataclass(frozen=True)
class WitnessSigner:
    key: WitnessKey
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)
    clock: Callable[[], int] = field(default=_clock, repr=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.private_key, ec.EllipticCurvePrivateKey)
                or not isinstance(self.private_key.curve, ec.SECP256R1)
                or self.private_key.public_key().public_numbers()
                != self.key.public_key.public_numbers()):
            raise WitnessRejected()

    def sign_verified(self, claims: Mapping, *, issued_at: int, lifetime: int = 900) -> str:
        """Sign already verified bindings with a bounded timestamp claim.

        issued_at must be the verified record's issuedAt, assigned by the future
        server preparation flow. The independent server clock refuses future or
        >300-second-old requests. No skew expands either end of a key window.
        Session authentication alone never authorizes this call.
        """
        now = self.clock()
        if (not _integer(now) or not _integer(issued_at) or not _integer(lifetime)
                or not 1 <= lifetime <= 900 or issued_at + lifetime > MAX_INTEGER
                or not self.key.not_before <= issued_at <= now < self.key.not_after
                or now - issued_at > 300 or issued_at + lifetime <= now):
            raise WitnessRejected()
        payload = dict(claims)
        if "iat" in payload or "exp" in payload:
            raise WitnessRejected()
        payload.update(iat=issued_at, exp=issued_at + lifetime)
        try:
            encoded = _json({"alg": "ES256", "kid": self.key.kid, "typ": "JWT"}) + "." + _json(payload)
        except (TypeError, ValueError, OverflowError):
            raise WitnessRejected() from None
        # Compact signature adds one dot and 86 unpadded base64url characters.
        if len(encoded) + 87 > 16384:
            raise WitnessRejected()
        der = self.private_key.sign(encoded.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        # SociACL requires canonical compact P-256 signatures, including low S.
        signature = r.to_bytes(32, "big") + min(s, P256_ORDER - s).to_bytes(32, "big")
        finished = self.clock()
        if (not _integer(finished) or not now <= finished < self.key.not_after
                or finished >= issued_at + lifetime):
            raise WitnessRejected()
        return encoded + "." + _b64(signature)
