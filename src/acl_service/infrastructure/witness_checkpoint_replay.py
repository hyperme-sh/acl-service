"""Durably consume an authenticated refresh challenge before issuance.

The replay database must be independently protected from reset/rollback. This is
not enrollment storage, revocation serialization, or an HTTP endpoint.
"""
import hashlib
import json
import time

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from controlplane_db.models import SociaclCheckpointRequest
from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure.witness_checkpoint_authorization import RefreshEnrollment
from acl_service.infrastructure.witness_signer import WitnessRejected


def sign_refresh_once(enrollment: RefreshEnrollment, replay_engine, body, authorization,
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
    try:
        if replay_engine.dialect.name != 'postgresql':
            raise WitnessRejected()
        with replay_engine.begin() as connection:
            # Force WAL flush before reporting consumption even if the role's
            # default is asynchronous. A replica/backup rollback still needs
            # independent operational protection.
            connection.execute(text('SET LOCAL synchronous_commit = on'))
            # Transaction-local settings cannot leak to later pooled borrowers.
            # Bound contention and statement execution separately from the
            # credential lease; neither timeout permits signing on uncertainty.
            connection.execute(text("SELECT set_config('lock_timeout', :timeout, true), "
                                    "set_config('statement_timeout', :timeout, true)"),
                               {'timeout': f'{replay_timeout_ms}ms'})
            result = connection.execute(insert(SociaclCheckpointRequest).values(
                request_hash=key, consumed_at=now).on_conflict_do_nothing().returning(
                    SociaclCheckpointRequest.request_hash)).scalar_one_or_none()
            if result is None:
                raise WitnessRejected()
    except SQLAlchemyError:
        raise WitnessRejected() from None
    # Include time spent waiting for the replay commit in enrollment freshness.
    def bounded_clock():
        current, elapsed = issuer._sample(clock, monotonic)
        if not now <= current < enrollment.expires_at or not started <= elapsed < started + enrollment.expires_at - now:
            raise WitnessRejected()
        return current
    return enrollment.sign_refresh(body, authorization, continuity_source, policy_reader,
        policy_payload, policy_signature, policy_root, management_private_key=management_private_key,
        lifetime=lifetime, clock=bounded_clock, monotonic=monotonic)
