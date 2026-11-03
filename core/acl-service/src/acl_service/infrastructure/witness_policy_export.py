"""Export an authenticated bundle only when it matches installed witness policy."""
import base64

from sqlalchemy import select
from sqlalchemy.orm import Session

from controlplane_db.models import SociaclWitnessPolicy
from acl_service.infrastructure.witness_policy_ingest import verify_policy
from acl_service.infrastructure.witness_signer import WitnessRejected, public_jwks


def export_signed_policy(engine, payload: bytes, signature: bytes, root_key, audience: str) -> dict:
    """Return exact signed bytes, never a reserialized or newly signed policy.

    This is a snapshot export, not a freshness guarantee at subsequent delivery.
    Recipients must authenticate it and enforce their own durable revision floor.
    """
    verified = verify_policy(payload, signature, root_key, audience)
    jwks = public_jwks(verified.keys)
    jwks["keys"].sort(key=lambda key: key["kid"])
    with Session(engine) as session, session.begin():
        row = session.scalars(select(SociaclWitnessPolicy)
                              .where(SociaclWitnessPolicy.id == 1)
                              .with_for_update(read=True)).one_or_none()
        verified.check_current()
        if row is None or row.revision != verified.revision or row.jwks != jwks:
            raise WitnessRejected()
        return {
            "type": "sociacl-witness-policy-envelope-v1",
            "payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }
