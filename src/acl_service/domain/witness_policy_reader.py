"""Backend-neutral serialized witness policy reads.

Adapters must hold a read lease against policy writers until context exit.
Snapshots are detached; callers recheck authorization freshness under the lease.
This interface does not authenticate policy updates or provide delivery freshness.
"""
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PolicySnapshot:
    revision: int
    jwks: dict


class WitnessPolicyReader(Protocol):
    def locked_policy(self) -> AbstractContextManager[PolicySnapshot | None]:
        """Read current installed policy, serialized against updates until exit."""
        ...


@dataclass(frozen=True)
class PolicyHistorySnapshot:
    """Detached trusted storage state; current signatures do not attest history."""
    revision: int
    jwks: dict
    history: dict


class WitnessPolicyHistoryReader(Protocol):
    def locked_history(self) -> AbstractContextManager[PolicyHistorySnapshot | None]:
        """Read complete history and policy atomically; block writers until exit.

        Never synthesize history from active keys. Adapters must propagate read
        and context-exit failures; consumers cannot publish before successful exit.
        """
        ...
