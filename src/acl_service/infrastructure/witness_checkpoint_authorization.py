"""Refresh-only credential boundary; no account-login or enrollment fallback."""
from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import re
import time

from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure.witness_policy_ingest import _object
from acl_service.infrastructure.witness_signer import MAX_INTEGER, WitnessRejected

MAX_REQUEST_BYTES = 8192


def _label(value):
    return isinstance(value, str) and 1 <= len(value.encode('utf-8')) <= 1024


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        raise WitnessRejected()
    raw = base64.urlsafe_b64decode(value + '=')
    if issuer._b64(raw) != value:
        raise WitnessRejected()
    return raw


@dataclass(frozen=True)
class RefreshEnrollment:
    """Independently provisioned scope and hash of a random 32-byte credential.

    This object does not enroll anyone. Its source and update/revocation process
    must be managed separately from requests and the policy database.
    """
    client: str
    audience: str
    root_epoch: int
    credential_sha256: bytes
    not_before: int
    expires_at: int

    def authorize(self, body: bytes, authorization: str, now: int):
        try:
            if (not _label(self.client) or not _label(self.audience)
                    or type(self.root_epoch) is not int or not 1 <= self.root_epoch <= MAX_INTEGER
                    or type(self.credential_sha256) is not bytes or len(self.credential_sha256) != 32
                    or any(type(n) is not int or not 0 <= n <= MAX_INTEGER
                           for n in (self.not_before, self.expires_at, now))
                    or not self.not_before <= now < self.expires_at
                    or type(body) is not bytes or not 0 < len(body) <= MAX_REQUEST_BYTES
                    or not isinstance(authorization, str) or len(authorization) != 50
                    or not authorization.startswith('Bearer ')):
                raise WitnessRejected()
            token = _secret(authorization[7:])
            if not hmac.compare_digest(hashlib.sha256(token).digest(), self.credential_sha256):
                raise WitnessRejected()
            request = json.loads(body.decode('utf-8'), object_pairs_hook=_object)
            if (type(request) is not dict or set(request) != {
                    'type', 'operation', 'client', 'audience', 'rootEpoch', 'challenge'}
                    or request['type'] != 'sociacl-witness-checkpoint-request-v1'
                    or request['operation'] != 'refresh'
                    or request['client'] != self.client or request['audience'] != self.audience
                    or type(request['rootEpoch']) is not int or request['rootEpoch'] != self.root_epoch):
                raise WitnessRejected()
            _secret(request['challenge'])
            return request['challenge']
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise WitnessRejected() from None

    def sign_refresh(self, body, authorization, continuity_source, policy_reader,
                     policy_payload, policy_signature, policy_root, *, management_private_key,
                     lifetime=300, clock=issuer._clock, monotonic=time.monotonic):
        """Authorize scope before any source/DB access, preserving credential lease.

        Caller must serialize enrollment revocation and consume the challenge in
        durable replay storage before invoking this method. No HTTP route is enabled.
        Immutable enrollment configuration must not be silently restored or updated.
        """
        initial, started = issuer._sample(clock, monotonic)
        challenge = self.authorize(body, authorization, initial)
        if continuity_source.root_epoch != self.root_epoch:
            raise WitnessRejected()
        def validate_authorization():
            now, elapsed = issuer._sample(clock, monotonic)
            if not initial <= now or not started <= elapsed < started + self.expires_at - initial:
                raise WitnessRejected()
            self.authorize(body, authorization, now)
        return continuity_source.sign_for_verified_refresh(
            policy_reader, policy_payload, policy_signature, policy_root, self.audience,
            management_private_key=management_private_key, client=self.client,
            challenge=challenge, lifetime=lifetime, clock=clock, monotonic=monotonic,
            expires_at_limit=self.expires_at, validate_before_return=validate_authorization)
