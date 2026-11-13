"""Offline atomic inbox/handler contracts; real SQL combinations run nightly."""
import uuid
import pytest
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.payloads.user_created import UserCreatedEvent
from acl_service.infrastructure.user_created_consumer import build_user_created_consumer
from test_policy_store import MemoryPolicyStore
from memory_atomic import install


def fact(tenant=None):
    tenant=tenant or uuid.uuid4()
    return ControlPlaneEventEnvelope(event_type='user.created.v1',service='user-service',tenant_id=tenant,
        payload=UserCreatedEvent(user_id=uuid.uuid4(),email='unit@example.com',tenant_id=str(tenant)).to_envelope_payload())


@pytest.mark.asyncio
async def test_message_retry_commits_once():
    store=MemoryPolicyStore();events,inbox=install(store);consumer=build_user_created_consumer(store)
    event_id=uuid.uuid4();envelope=fact()
    assert await consumer.receive(event_id,envelope)
    assert not await consumer.receive(event_id,envelope)
    assert len(store.rows)==len(events)==len(inbox)==1


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_inbox_and_policy():
    store=MemoryPolicyStore();events,inbox=install(store,fail=True)
    with pytest.raises(RuntimeError,match='outbox refused'):
        await build_user_created_consumer(store).receive(uuid.uuid4(),fact())
    assert not store.rows and not events and not inbox


@pytest.mark.asyncio
async def test_reused_delivery_id_cannot_change_facts():
    store=MemoryPolicyStore();events,inbox=install(store);consumer=build_user_created_consumer(store)
    event_id=uuid.uuid4();envelope=fact()
    await consumer.receive(event_id,envelope)
    with pytest.raises(ValueError,match='reused'):
        await consumer.receive(event_id,fact(envelope.tenant_id))
    assert len(store.rows)==len(events)==len(inbox)==1


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value',[('tenant_id',None),('service','payment-service'),('event_type','payment.succeeded.v1')])
async def test_wrong_owner_or_scope_is_refused(field,value):
    store=MemoryPolicyStore();events,inbox=install(store)
    envelope=fact().model_copy(update={field:value})
    with pytest.raises(ValueError):await build_user_created_consumer(store).receive(uuid.uuid4(),envelope)
    assert not store.rows and not events and not inbox
