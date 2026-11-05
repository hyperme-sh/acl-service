"""user.created.v1 → default per-user RBAC policy."""

from __future__ import annotations

import asyncio

from acl_service.domain.policy_store import PolicyStore

from controlplane_api.event_types import ACL_POLICY_UPDATED_V1, USER_CREATED_V1
from controlplane_api.config import settings
from api.infrastructure.messaging.tenant_event_publisher import (
    build_routing_consumer,
    get_tenant_event_publisher,
)
from controlplane_events.payloads import AclPolicyUpdatedPayload
from controlplane_events.payloads.user_created import UserCreatedEvent
from acl_service.domain.policy_store import add_rule_if_absent

ACL_USER_CREATED_GROUP = "acl-service-controlplane-events"


def build_user_created_consumer(store: PolicyStore, database_url: str):
    async def on_user_created(_envelope, payload: UserCreatedEvent) -> None:
        tid = _envelope.tenant_id
        if tid is None:
            return

        uid = payload.user_id
        rule = [str(uid), "user_profile", "read"]

        def _add() -> bool:
            return add_rule_if_absent(store, tid, "p", rule)

        # The rule may already exist from an earlier path that never published
        # acl.policy.updated. Emit the event either way. The rule insert itself
        # stays idempotent.
        await asyncio.to_thread(_add)

        preview = ",".join(["p", *rule])[:512]
        await get_tenant_event_publisher().publish(
            tenant_id=tid,
            event_type=ACL_POLICY_UPDATED_V1,
            payload=AclPolicyUpdatedPayload(
                tenant_id=tid,
                operation="added",
                ptype="p",
                actor_sub="system:user-created-consumer",
                rule_preview=preview,
            ).to_envelope_payload(),
        )

    return build_routing_consumer(
        database_url=database_url,
        group_id=ACL_USER_CREATED_GROUP,
        routes={USER_CREATED_V1: (UserCreatedEvent, on_user_created)},
        client_id="acl-service-user-events",
        service_bus_connection_string=settings.azure_service_bus_connection_string,
    )
