"""Internal checkpoint signer for already-authorized management refreshes.

No endpoint, enrollment authorization, challenge consumption or protected management
store is provided. Continuity must come from independent rollback-protected state,
never from the database snapshot being signed or from request fields.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acl_service.infrastructure.witness_policy_snapshot import locked_complete_policy_snapshot
from acl_service.infrastructure.witness_signer import MAX_INTEGER, P256_ORDER, WitnessRejected

DOMAIN = b"sociacl-witness-checkpoint-v1\n"
MAX_PAYLOAD_BYTES = 2105344
MAX_ENVELOPE_BYTES = 3145728
MAX_RESPONSE_BYTES = 4194304


@dataclass(frozen=True)
class CheckpointContinuity:
    """Trusted management epoch and SHA-256 of canonical complete policy state.

    This data class is not proof of provenance or authorization. The caller must
    authenticate its independently protected source before invoking the signer.
    """
    root_epoch: int
    state_sha256: bytes


def _json(value, *, sort_keys=False):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=sort_keys, allow_nan=False).encode("utf-8")


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _clock():
    return int(time.time())


def _sample(clock, monotonic):
    now, elapsed = clock(), monotonic()
    if (type(now) is not int or not 0 <= now <= MAX_INTEGER
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0):
        raise WitnessRejected()
    return now, elapsed


def _sign_payload(private_key, payload):
    der = private_key.sign(DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + min(s, P256_ORDER - s).to_bytes(32, "big")


def sign_checkpoint_for_verified_refresh(
        engine, policy_payload: bytes, policy_signature: bytes, policy_root, audience: str,
        *, management_private_key, continuity: CheckpointContinuity, client: str,
        challenge: str, lifetime: int = 300, clock: Callable[[], int] = _clock,
        monotonic: Callable[[], float] = time.monotonic) -> str:
    """Return the v1 response JSON only after locked signing and expiry checks.

    The caller must authorize the enrollment/client and consume its request once
    under management continuity serialization before calling. Account login alone
    is insufficient. Neither a continuity object nor this function authenticates
    those decisions. Root migration and recovery require separate authorization.
    """
    try:
        if (not isinstance(management_private_key, ec.EllipticCurvePrivateKey)
                or not isinstance(management_private_key.curve, ec.SECP256R1)
                or not isinstance(continuity, CheckpointContinuity)
                or type(continuity.root_epoch) is not int or not 1 <= continuity.root_epoch <= MAX_INTEGER
                or type(continuity.state_sha256) is not bytes or len(continuity.state_sha256) != 32
                or type(lifetime) is not int or not 1 <= lifetime <= 300
                or any(not isinstance(label, str) or not 1 <= len(label.encode('utf-8')) <= 1024
                       for label in (audience, client))
                or not isinstance(challenge, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', challenge)
                or _b64(base64.urlsafe_b64decode(challenge + '=')) != challenge):
            raise WitnessRejected()
        initial_time, initial_elapsed = _sample(clock, monotonic)
        management_point = management_private_key.public_key().public_numbers()
        management_root = _b64(management_point.x.to_bytes(32, 'big')) + '.' + _b64(management_point.y.to_bytes(32, 'big'))
        with locked_complete_policy_snapshot(engine, policy_payload, policy_signature, policy_root, audience) as snapshot:
            state = json.loads(snapshot.state_json)
            if (state['root'] == management_root
                    or any(entry['jwk']['x'] + '.' + entry['jwk']['y'] == management_root for entry in state['history'])
                    or not hmac.compare_digest(hashlib.sha256(_json(state, sort_keys=True)).digest(), continuity.state_sha256)):
                raise WitnessRejected()
            issued, started = _sample(clock, monotonic)
            if issued < initial_time or started < initial_elapsed:
                raise WitnessRejected()
            expires = min(issued + lifetime, snapshot.expires_at, MAX_INTEGER)
            if expires <= issued:
                raise WitnessRejected()
            payload = _json({'type': 'sociacl-witness-checkpoint-v1', 'audience': audience,
                'client': client, 'challenge': challenge, 'rootEpoch': continuity.root_epoch,
                'issuedAt': issued, 'expiresAt': expires, 'state': state})
            if len(payload) > MAX_PAYLOAD_BYTES:
                raise WitnessRejected()
            envelope = _json({'type': 'sociacl-witness-checkpoint-envelope-v1',
                'payload': _b64(payload), 'signature': _b64(_sign_payload(management_private_key, payload))})
            if len(envelope) > MAX_ENVELOPE_BYTES:
                raise WitnessRejected()
            response = _json({'type': 'sociacl-witness-checkpoint-response-v1',
                'checkpoint': envelope.decode('utf-8'), 'policy': snapshot.policy_json})
            if len(response) > MAX_RESPONSE_BYTES:
                raise WitnessRejected()
        # Includes context exit/transaction completion. A stalled UTC clock cannot
        # extend signing past the lease; backward observations also fail closed.
        finished, elapsed = _sample(clock, monotonic)
        if not issued <= finished < expires or not started <= elapsed < started + expires - issued:
            raise WitnessRejected()
        return response.decode('utf-8')
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        raise WitnessRejected() from None
