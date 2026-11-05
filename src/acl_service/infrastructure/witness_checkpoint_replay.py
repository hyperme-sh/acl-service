"""Durably consume an authenticated refresh challenge before issuance.

The replay database must be independently protected from reset/rollback. This is
not enrollment storage, revocation serialization, or an HTTP endpoint.
"""
import hashlib
import json
import time

from acl_service.domain.checkpoint_replay_store import CheckpointReplayStore
from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure.witness_checkpoint_authorization import RefreshEnrollment
from acl_service.infrastructure.witness_signer import WitnessRejected


def sign_refresh_once(enrollment: RefreshEnrollment, replay_store: CheckpointReplayStore, body, authorization,
                      continuity_source, policy_reader, policy_payload, policy_signature, policy_root,
                      *, management_private_key, lifetime=300, clock=issuer._clock,
                      monotonic=time.monotonic, replay_timeout_ms=1000):
    """Commit consumption before signing; never release it on a lost/failed response.

    The caller must hold the management enrollment/revocation serialization boundary
    throughout this operation. Database commit uncertainty fails closed; retry must
    use a new challenge. Credentials, policy revisions and pin rotation are not part
    of the replay namespace, so changing those cannot reset consumption.
    """
    if (not isinstance(enrollment, RefreshEnrollment)
            or type(replay_timeout_ms) is not int or not 1 <= replay_timeout_ms <= 5000):
        raise WitnessRejected()
    now, started = issuer._sample(clock, monotonic)
    challenge = enrollment.authorize(body, authorization, now)
    if continuity_source.root_epoch != enrollment.root_epoch:
        raise WitnessRejected()
    key = hashlib.sha256(json.dumps(
        ['sociacl-checkpoint-consumption-v1', enrollment.audience, enrollment.client,
         enrollment.root_epoch, challenge], ensure_ascii=False, separators=(',', ':')
    ).encode('utf-8')).hexdigest()
    replay_store.consume(key, now, timeout_ms=replay_timeout_ms)
    # Include time spent waiting for the replay commit in enrollment freshness.
    def bounded_clock():
        current, elapsed = issuer._sample(clock, monotonic)
        if not now <= current < enrollment.expires_at or not started <= elapsed < started + enrollment.expires_at - now:
            raise WitnessRejected()
        return current
    return enrollment.sign_refresh(body, authorization, continuity_source, policy_reader,
        policy_payload, policy_signature, policy_root, management_private_key=management_private_key,
        lifetime=lifetime, clock=bounded_clock, monotonic=monotonic)
