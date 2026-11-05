"""Timestamp signing under a serialized trusted policy lease."""
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from acl_service.domain.witness_policy_reader import WitnessPolicyReader
from acl_service.infrastructure.witness_signer import WitnessKey, WitnessRejected, WitnessSigner


def sign_with_policy(reader: WitnessPolicyReader, kid: str, private_key, claims, *, issued_at: int, lifetime: int = 900) -> str:
    """Sign verified claims under current durable policy, serialized with updates.

    Same authorization obligations as WitnessSigner.sign_verified. No policy/key
    metadata may be cached across calls. Returning a token does not grant access.
    """
    with reader.locked_policy() as row:
        if row is None:
            raise WitnessRejected()
        jwk = next((key for key in row.jwks["keys"] if key["kid"] == kid), None)
        if jwk is None:
            raise WitnessRejected()
        def coordinate(value):
            return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")
        public = ec.EllipticCurvePublicNumbers(coordinate(jwk["x"]), coordinate(jwk["y"]), ec.SECP256R1()).public_key()
        key = WitnessKey(kid, jwk["notBefore"], jwk["notAfter"], public)
        token = WitnessSigner(key, private_key).sign_verified(claims, issued_at=issued_at, lifetime=lifetime)
    return token
