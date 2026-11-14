"""Bounded signed allocation wire contract; no issuer, storage or HTTP activation."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
from typing import Mapping
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"spanopticon-media-allocation-v1\x00"
MAX_GRANT_BYTES = 4096
MAX_GRANT_SECONDS = 300
MAX_INTEGER = 2**53 - 1
_SCOPE_FIELDS = {"issuer", "tenant", "object", "owner", "source", "policyDigest", "ownershipDigest"}
_CLAIM_FIELDS = _SCOPE_FIELDS | {"version", "allocation", "issuedAt", "expiresAt"}


class AllocationRejected(ValueError):
    """The supplied proof cannot be used for the expected protected source."""


def _uuid(value: object) -> str:
    if type(value) is not str:
        raise AllocationRejected("Invalid allocation identifier")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise AllocationRejected("Invalid allocation identifier") from exc
    if not parsed.int or str(parsed) != value:
        raise AllocationRejected("Invalid allocation identifier")
    return value


def _b64(value: object, size: int) -> bytes:
    if type(value) is not str or len(value) != (size * 8 + 5) // 6 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AllocationRejected("Invalid allocation encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != size or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise AllocationRejected("Invalid allocation encoding")
    return raw


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise AllocationRejected("Invalid allocation time")
    return value


@dataclass(frozen=True)
class AllocationScope:
    """Expected values supplied by trusted configuration/current owner checks."""
    issuer: str
    tenant: str
    object: str
    owner: str
    source: str
    policy_digest: str
    ownership_digest: str

    def claims(self) -> dict:
        for value in (self.issuer, self.tenant, self.source):
            _uuid(value)
        for value in (self.policy_digest, self.ownership_digest):
            if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise AllocationRejected("Invalid allocation digest")
        if type(self.owner) is not str or len(self.owner) != 87 or self.owner.count(".") != 1:
            raise AllocationRejected("Invalid allocation owner")
        x, y = (_b64(part, 32) for part in self.owner.split("."))
        try:
            ec.EllipticCurvePublicNumbers(int.from_bytes(x), int.from_bytes(y), ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise AllocationRejected("Invalid allocation owner") from exc
        prefix = "media_p_" + (x + y).hex() + "_"
        if type(self.object) is not str or not self.object.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{32}", self.object[len(prefix):]):
            raise AllocationRejected("Allocation object does not belong to owner")
        return {"issuer": self.issuer, "tenant": self.tenant, "object": self.object, "owner": self.owner,
                "source": self.source, "policyDigest": self.policy_digest, "ownershipDigest": self.ownership_digest}


@dataclass(frozen=True)
class VerifiedAllocation:
    """Signature and scope only. The source must atomically consume allocation."""
    scope: AllocationScope
    allocation: str
    issued_at: int
    expires_at: int


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise AllocationRejected("Duplicate allocation property")
    return result


def canonical_message(key_id: str, claims: dict, *, domain: bytes = DOMAIN) -> bytes:
    """Domain separation also binds key selection. Inputs still need validation."""
    return domain + json.dumps({"keyId": key_id, "claims": claims}, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _verify_allocation(raw: bytes, *, domain: bytes, expected: AllocationScope,
                            keys: Mapping[str, Ed25519PublicKey], now: int) -> VerifiedAllocation:
    """No key discovery, identity enrollment, policy import or replay-state reset.

    Call only with independently configured keys and expected scope. A matching
    signature does not replace the issuer's exclusive allocation ledger or the
    consumer's atomic one-use initialization and independent checkpoint.
    """
    _integer(now)
    wanted = expected.claims()
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_GRANT_BYTES or not 1 <= len(keys) <= 16:
        raise AllocationRejected("Invalid allocation envelope")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AllocationRejected("Invalid allocation envelope") from exc
    if type(envelope) is not dict or set(envelope) != {"keyId", "claims", "signature"}:
        raise AllocationRejected("Invalid allocation envelope")
    key_id, claims = envelope["keyId"], envelope["claims"]
    if type(key_id) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id):
        raise AllocationRejected("Invalid allocation key")
    key = keys.get(key_id)
    if not isinstance(key, Ed25519PublicKey):
        raise AllocationRejected("Untrusted allocation key")
    if type(claims) is not dict or set(claims) != _CLAIM_FIELDS or type(claims["version"]) is not int or claims["version"] != 1:
        raise AllocationRejected("Invalid allocation claims")
    if any(claims[name] != value or type(claims[name]) is not str for name, value in wanted.items()):
        raise AllocationRejected("Allocation scope mismatch")
    allocation = _uuid(claims["allocation"])
    issued, expires = _integer(claims["issuedAt"]), _integer(claims["expiresAt"])
    if not issued <= now < expires or not 0 < expires - issued <= MAX_GRANT_SECONDS:
        raise AllocationRejected("Allocation expired or not current")
    signature = _b64(envelope["signature"], 64)
    try:
        key.verify(signature, canonical_message(key_id, claims, domain=domain))
    except InvalidSignature as exc:
        raise AllocationRejected("Invalid allocation signature") from exc
    return VerifiedAllocation(expected, allocation, issued, expires)


def verify_allocation_grant(raw: bytes, *, expected: AllocationScope,
                            keys: Mapping[str, Ed25519PublicKey], now: int) -> VerifiedAllocation:
    return _verify_allocation(raw, domain=DOMAIN, expected=expected, keys=keys, now=now)


REQUEST_DOMAIN = b"spanopticon-media-allocation-request-v1\x00"


def verify_allocation_request(raw: bytes, *, expected: AllocationScope,
                              keys: Mapping[str, Ed25519PublicKey], now: int) -> VerifiedAllocation:
    """A configured protected source attests its current ownership/policy check.

    The source must verify current SEA ownership before signing. Its request key
    is distinct from the storage issuer key. A request is never a storage grant.
    The allocation field is a request nonce; storage chooses the durable ID.
    """
    request = _verify_allocation(raw, domain=REQUEST_DOMAIN, expected=expected, keys=keys, now=now)
    if request.expires_at - request.issued_at > 30:
        raise AllocationRejected("Allocation request exceeds validity limit")
    return request
