"""PostgreSQL durable checkpoint challenge consumption."""
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from controlplane_db.models import SociaclCheckpointRequest
from acl_service.infrastructure.witness_signer import WitnessRejected


class PostgresCheckpointReplayStore:
    def __init__(self, engine):
        self._engine = engine

    def consume(self, request_hash: str, consumed_at: int, *, timeout_ms: int) -> None:
        if (type(timeout_ms) is not int or not 1 <= timeout_ms <= 5000):
            raise WitnessRejected()
        try:
            if self._engine.dialect.name != 'postgresql':
                raise WitnessRejected()
            with self._engine.begin() as connection:
                # Force WAL flush before reporting consumption even if the role's
                # default is asynchronous. A replica/backup rollback still needs
                # independent operational protection.
                connection.execute(text('SET LOCAL synchronous_commit = on'))
                # Transaction-local settings cannot leak to later pooled borrowers.
                # Bound contention and statement execution separately from the
                # credential lease; neither timeout permits signing on uncertainty.
                connection.execute(text("SELECT set_config('lock_timeout', :timeout, true), "
                                        "set_config('statement_timeout', :timeout, true)"),
                                   {'timeout': f'{timeout_ms}ms'})
                result = connection.execute(insert(SociaclCheckpointRequest).values(
                    request_hash=request_hash, consumed_at=consumed_at).on_conflict_do_nothing().returning(
                        SociaclCheckpointRequest.request_hash)).scalar_one_or_none()
                if result is None:
                    raise WitnessRejected()
        except SQLAlchemyError:
            raise WitnessRejected() from None
