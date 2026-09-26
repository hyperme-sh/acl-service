"""Tests for user.created consumer (handler logic)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.common.event_types import ACL_POLICY_UPDATED_V1, USER_CREATED_V1
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.payloads import PaymentSucceededPayload
from controlplane_events.payloads.user_created import UserCreatedEvent

from acl_service.infrastructure.user_created_consumer import build_user_created_consumer


@pytest.mark.asyncio
async def test_user_created_adds_policy_and_emits():
    tid = uuid.uuid4()
    uid = uuid.uuid4()
    sync_eng = MagicMock()
    mock_publish = AsyncMock()

    consumer = build_user_created_consumer(
        sync_eng,
        "postgresql://localhost/controlplane",
    )

    with patch(
        "acl_service.infrastructure.user_created_consumer.add_rule"
    ) as add_rule, patch(
        "acl_service.infrastructure.user_created_consumer.get_tenant_event_publisher",
        return_value=MagicMock(publish=mock_publish),
    ):
        env = ControlPlaneEventEnvelope(
            event_type=USER_CREATED_V1,
            service="user-service",
            tenant_id=tid,
            payload=UserCreatedEvent(
                user_id=uid,
                email="u@example.com",
                tenant_id=str(tid),
            ).to_envelope_payload(),
        )
        await consumer.handle_message(
            key=None,
            value=env.model_dump_json().encode("utf-8"),
            headers={},
        )

    add_rule.assert_called_once_with(
        sync_eng,
        tid,
        "p",
        [str(uid), "user_profile", "read"],
    )
    mock_publish.assert_awaited_once()
    call = mock_publish.await_args
    assert call.kwargs["tenant_id"] == tid
    assert call.kwargs["event_type"] == ACL_POLICY_UPDATED_V1


@pytest.mark.asyncio
async def test_user_created_skips_without_tenant_envelope():
    sync_eng = MagicMock()
    mock_publish = AsyncMock()
    consumer = build_user_created_consumer(sync_eng, "postgresql://localhost/controlplane")

    with patch(
        "acl_service.infrastructure.user_created_consumer.add_rule"
    ) as add_rule, patch(
        "acl_service.infrastructure.user_created_consumer.get_tenant_event_publisher",
        return_value=MagicMock(publish=mock_publish),
    ):
        uid = uuid.uuid4()
        env = ControlPlaneEventEnvelope(
            event_type=USER_CREATED_V1,
            service="user-service",
            tenant_id=None,
            payload=UserCreatedEvent(
                user_id=uid,
                email="u@example.com",
                tenant_id=None,
            ).to_envelope_payload(),
        )
        await consumer.handle_message(
            key=None,
            value=env.model_dump_json().encode("utf-8"),
            headers={},
        )

    add_rule.assert_not_called()
    mock_publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_routing_ignores_other_event_types():
    sync_eng = MagicMock()
    consumer = build_user_created_consumer(sync_eng, "postgresql://localhost/controlplane")

    with patch("acl_service.infrastructure.user_created_consumer.add_rule") as add_rule:
        tid = uuid.uuid4()
        env = ControlPlaneEventEnvelope(
            event_type="payment.succeeded.v1",
            service="payment-service",
            tenant_id=tid,
            payload=PaymentSucceededPayload(
                tenant_id=tid,
                billing_record_id=uuid.uuid4(),
            ).to_envelope_payload(),
        )
        await consumer.handle_message(
            key=None,
            value=env.model_dump_json().encode("utf-8"),
            headers={},
        )

    add_rule.assert_not_called()
