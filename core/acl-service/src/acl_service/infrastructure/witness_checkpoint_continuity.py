"""Pinned operator continuity for an already-authorized checkpoint refresh.

The pin is independent deployment trust, not a value from the document, policy
store or HTTP request. Pin custody and rollback protection remain operator duties.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import time

from cryptography.hazmat.primitives.asymmetric import ec

from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure.witness_policy_ingest import _object
from acl_service.infrastructure.witness_policy_publication import read_regular_file
from acl_service.infrastructure.witness_signer import MAX_INTEGER, WitnessRejected

MAX_CONTINUITY_BYTES = 8192
MAX_CONTINUITY_LIFETIME = 86400


def _public(key):
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise WitnessRejected()
    point = key.public_numbers()
    return issuer._b64(point.x.to_bytes(32, 'big')) + '.' + issuer._b64(point.y.to_bytes(32, 'big'))


@dataclass(frozen=True)
class PinnedCheckpointContinuity:
    """Immutable configuration supplied through an independent operator channel.

    The digest authenticates exact document bytes. Never derive it from the file
    at startup. Updates require a separately authorized replacement of this pin;
    copying or restoring the policy database must not change it.
    """
    document_file: Path
    document_sha256: bytes
    root_epoch: int

    def _read(self, *, audience, policy_root, management_key, now):
        try:
            if (not isinstance(self.document_file, Path) or not self.document_file.is_absolute()
                    or type(self.document_sha256) is not bytes or len(self.document_sha256) != 32
                    or type(self.root_epoch) is not int or not 1 <= self.root_epoch <= MAX_INTEGER
                    or type(now) is not int or not 0 <= now <= MAX_INTEGER):
                raise WitnessRejected()
            raw = read_regular_file(self.document_file, MAX_CONTINUITY_BYTES)
            if not hmac.compare_digest(hashlib.sha256(raw).digest(), self.document_sha256):
                raise WitnessRejected()
            doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_object)
            if (type(doc) is not dict or set(doc) != {
                    'type', 'audience', 'root', 'managementRoot', 'rootEpoch',
                    'stateSha256', 'issuedAt', 'expiresAt'}
                    or doc['type'] != 'sociacl-witness-continuity-v1'
                    or doc['audience'] != audience or not isinstance(audience, str) or not audience
                    or doc['root'] != _public(policy_root)
                    or doc['managementRoot'] != _public(management_key)
                    or type(doc['rootEpoch']) is not int or doc['rootEpoch'] != self.root_epoch
                    or not isinstance(doc['stateSha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', doc['stateSha256'])
                    or any(type(doc[k]) is not int or not 0 <= doc[k] <= MAX_INTEGER
                           for k in ('issuedAt', 'expiresAt'))
                    or not 0 < doc['expiresAt'] - doc['issuedAt'] <= MAX_CONTINUITY_LIFETIME
                    or not doc['issuedAt'] <= now < doc['expiresAt']):
                raise WitnessRejected()
            return issuer.CheckpointContinuity(self.root_epoch, bytes.fromhex(doc['stateSha256'])), doc['expiresAt']
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise WitnessRejected() from None

    def sign_for_verified_refresh(self, engine, policy_payload, policy_signature, policy_root, audience,
                                  *, management_private_key, client, challenge, lifetime=300,
                                  clock=issuer._clock, monotonic=time.monotonic):
        """Authenticate continuity before signing; no enrollment or replay authority.

        The caller still authorizes the client and consumes its challenge under
        management serialization. No route or automatic pin update is provided.
        """
        if (not isinstance(management_private_key, ec.EllipticCurvePrivateKey)
                or type(lifetime) is not int or not 1 <= lifetime <= 300):
            raise WitnessRejected()
        now, started = issuer._sample(clock, monotonic)
        key = management_private_key.public_key()
        continuity, expires = self._read(audience=audience, policy_root=policy_root, management_key=key, now=now)
        # Clamp the signer's clock to the source lease too: a delay between reading
        # the source and sampling the signer cannot extend the issued lease.
        def bounded_clock():
            current, elapsed = issuer._sample(clock, monotonic)
            if not now <= current < expires or not started <= elapsed < started + expires - now:
                raise WitnessRejected()
            return current
        response = issuer.sign_checkpoint_for_verified_refresh(
            engine, policy_payload, policy_signature, policy_root, audience,
            management_private_key=management_private_key, continuity=continuity,
            client=client, challenge=challenge, lifetime=lifetime,
            clock=bounded_clock, monotonic=monotonic, expires_at_limit=expires)
        # Fail closed on loss/replacement during signing. Do not serve a cached
        # last-good document when an operator withdraws this authorization.
        self._read(audience=audience, policy_root=policy_root, management_key=key, now=bounded_clock())
        bounded_clock()  # Includes final file I/O, not just signature generation.
        return response
