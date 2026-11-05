"""Trusted policy installation boundary; never accepts unauthenticated updates."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, TYPE_CHECKING

from acl_service.domain.witness_policy_reader import PolicySnapshot

if TYPE_CHECKING:
    from acl_service.infrastructure.witness_signer import WitnessKey


class WitnessPolicyWriter(Protocol):
    def install_verified(
        self, revision: int, keys: Sequence[WitnessKey], *,
        check_authorization: Callable[[], None],
    ) -> PolicySnapshot:
        """Commit authenticated policy atomically with durable retirement history.

        Serialize against readers and writers; invoke check_authorization inside
        that critical section, including idempotent retries. Reject rollback,
        same-revision conflicts, widened windows, reused material and resurrection.
        A failed callback must leave no changes. Return a detached snapshot only
        after commit. Callers authenticate signatures and audience before entry.
        """
        ...
