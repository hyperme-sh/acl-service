"""Storage API for trusted ACL identity admission and recovery adapters.

Enrollment is only for identities under exclusive ACL admission from genesis.
The caller authenticates the principal and verifies each admission. A revision
orders commits and supports concurrency control; it is never a signing-key head.
"""
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class HistorySnapshot:
    principal: str
    genesis: bytes
    entries: tuple[bytes, ...]

    @property
    def revision(self) -> int:
        return len(self.entries)


class HistoryConflict(ValueError):
    """Enrollment exists or the expected history revision is no longer current."""


class HistoryStore(Protocol):
    def enroll(self, principal: str, genesis: bytes) -> None:
        """Create an exclusively managed principal once, after admission."""
        ...

    def append(self, principal: str, expected_revision: int, entry: bytes, *,
               authority_revision: int | None = None) -> None:
        """Commit an admitted record only against its verified predecessor snapshot."""
        ...

    def read_authority(self) -> tuple[int, dict[str, HistorySnapshot]]:
        """Return every enrolled history and a revision fencing any authority write."""
        ...

    def read(self, principal: str) -> HistorySnapshot | None:
        """Read genesis and every admitted entry in a single committed snapshot."""
        ...
