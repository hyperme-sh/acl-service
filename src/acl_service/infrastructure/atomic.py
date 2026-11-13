"""Owner SQL transaction shared by existing stores and derivative events."""
from contextlib import contextmanager
import json
import uuid
from sqlalchemy import Connection, bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.publisher import refuse_forbidden_payload

MAX_DELIVERY_BYTES = 262144
_INSERT = text('''INSERT INTO service_outbox(id,tenant_id,envelope)
VALUES (:id,:tenant,:envelope) ON CONFLICT (id) DO NOTHING RETURNING id''').bindparams(bindparam('envelope',type_=JSONB))


def store_session(bind):
    # Store-local commits release only a savepoint when an owner transaction
    # supplies a connection. Their rollback/retry paths cannot commit the owner.
    return Session(bind, join_transaction_mode='create_savepoint') if isinstance(bind,Connection) else Session(bind)


class Operation:
    def __init__(self, store, connection):
        self.store=store; self.connection=connection; self.events=[]

    def lock(self, key):
        self.connection.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:key,0))'),{'key':key})

    def emit(self, *, tenant_id, event_type, operation_id, payload):
        tenant=uuid.UUID(str(tenant_id))
        event_id=uuid.uuid5(uuid.NAMESPACE_URL,f'acl-service:{tenant}:{event_type}:{operation_id}')
        refuse_forbidden_payload(payload)
        envelope=ControlPlaneEventEnvelope(service='acl-service',tenant_id=tenant,event_type=event_type,payload=payload)
        validate_event_envelope(envelope)
        encoded=envelope.model_dump(mode='json')
        if len(json.dumps({'event_id':str(event_id),'envelope':encoded}).encode())>MAX_DELIVERY_BYTES:
            raise ValueError('ACL event exceeds delivery limit')
        self.connection.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':str(tenant)})
        self.connection.execute(text('INSERT INTO service_tenants(tenant_id) VALUES (:tenant) ON CONFLICT DO NOTHING'),{'tenant':tenant})
        inserted=self.connection.execute(_INSERT,{'id':event_id,'tenant':tenant,'envelope':encoded}).scalar_one_or_none()
        if inserted is None:
            prior=self.connection.execute(text('SELECT envelope FROM service_outbox WHERE id=:id AND tenant_id=:tenant'),{'id':event_id,'tenant':tenant}).scalar_one()
            if any(prior.get(k)!=encoded.get(k) for k in ('service','tenant_id','event_type','schema_version','payload')):
                raise ValueError('ACL operation conflicts with its event')
        else:self.events.append(encoded)
        return event_id


@contextmanager
def atomic_store(store):
    # Test/domain adapters can implement the same explicit operation contract.
    custom=getattr(store,'atomic',None)
    if custom is not None:
        with custom() as operation:yield operation
        return
    with store._engine.begin() as connection:
        operation=Operation(type(store)(connection),connection)
        yield operation
    sink=getattr(store,'event_sink',None)
    if sink is not None:sink.extend(operation.events)
