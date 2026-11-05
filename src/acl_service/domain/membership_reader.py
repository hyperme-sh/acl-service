"""Trusted, tenant-scoped membership lookup for authorization decisions.

The subject must come from authenticated same-tenant identity, never request
context. Implementations match that subject to an active, nondeleted user and
require user, group and membership to all belong to the requested tenant.
Storage/transport errors must propagate; stale positives must not be cached.
"""
from typing import Protocol
from uuid import UUID


class MembershipReader(Protocol):
    def user_in_group(self, tenant_id: UUID, subject: str, group_id: UUID) -> bool: ...
