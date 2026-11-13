"""Authenticated User facts become inbox, policy and outbox writes atomically."""
import asyncio
import json
import uuid
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from controlplane_api.event_types import ACL_POLICY_UPDATED_V1, USER_CREATED_V1
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.payloads import AclPolicyUpdatedPayload
from controlplane_events.payloads.user_created import UserCreatedEvent
from acl_service.infrastructure.atomic import atomic_store

_INBOX=text('''INSERT INTO event_inbox(event_id,tenant_id,envelope)
VALUES (:id,:tenant,:envelope) ON CONFLICT DO NOTHING RETURNING event_id''').bindparams(bindparam('envelope',type_=JSONB))


class UserCreatedConsumer:
    def __init__(self,store):self.store=store

    async def start(self):
        def ready():
            with self.store._engine.connect() as db:
                db.execute(text('SELECT 1 FROM event_inbox LIMIT 1'))
                db.execute(text('SELECT 1 FROM service_outbox LIMIT 1'))
        await asyncio.to_thread(ready)

    async def stop(self):pass

    def apply(self,event_id,envelope):
        if envelope.service!='user-service' or envelope.event_type!=USER_CREATED_V1 or envelope.tenant_id is None:
            raise ValueError('Only tenant-scoped user-service user.created events are accepted')
        if envelope.schema_version!=1:raise ValueError('Unsupported event envelope version')
        from jsonschema import ValidationError
        try:validate_event_envelope(envelope)
        except ValidationError:raise ValueError('Invalid user.created payload') from None
        payload=UserCreatedEvent.model_validate(envelope.payload)
        event_id=uuid.UUID(str(event_id));tenant=envelope.tenant_id
        encoded=envelope.model_dump(mode='json')
        rule=[str(payload.user_id),'user_profile','read']
        with atomic_store(self.store) as tx:
            tx.connection.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':str(tenant)})
            tx.lock('inbox:'+str(event_id))
            inserted=tx.connection.execute(_INBOX,{'id':event_id,'tenant':tenant,'envelope':encoded}).scalar_one_or_none()
            if inserted is None:
                previous=tx.connection.execute(text('SELECT envelope FROM event_inbox WHERE event_id=:id'),{'id':event_id}).scalar_one_or_none()
                if previous!=encoded:raise ValueError('Event identity reused with different facts')
                return False
            tx.lock(f'policy:{tenant}:p:{rule}')
            tx.store.add_rule(tenant,'p',rule)
            tx.emit(tenant_id=tenant,event_type=ACL_POLICY_UPDATED_V1,operation_id=str(event_id),
                payload=AclPolicyUpdatedPayload(tenant_id=tenant,operation='added',ptype='p',
                    actor_sub='system:user-created-consumer',rule_preview=','.join(['p',*rule])[:512]).to_envelope_payload())
        return True

    async def receive(self,event_id,envelope):
        return await asyncio.to_thread(self.apply,event_id,envelope)


def build_user_created_consumer(store, database_url=None):
    return UserCreatedConsumer(store)
