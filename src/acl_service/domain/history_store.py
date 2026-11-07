"""Storage API for trusted ACL identity admission and recovery adapters.

Enrollment is only for identities under exclusive ACL admission from genesis.
The caller authenticates the principal and verifies each admission. A revision
orders commits and supports concurrency control; it is never a signing-key head.
"""
from dataclasses import dataclass
from typing import Protocol

from acl_service.domain.keyring_store import StoreKind


@dataclass(frozen=True)
class HistorySnapshot:
    principal: str
    genesis: bytes
    entries: tuple[bytes, ...]

    @property
    def revision(self) -> int:
        return len(self.entries)


class AdmissionRejected(ValueError):
    """An enrolled-history verifier rejected the submitted operation."""


class HistoryConflict(ValueError):
    """Enrollment exists or the expected history revision is no longer current."""


class HistoryStore(Protocol):
    def enroll(self, principal: str, genesis: bytes) -> None:
        """Create an exclusively managed principal once, after admission."""
        ...

    def append(self, principal: str, expected_revision: int, entry: bytes, *,
               authority_revision: int | None = None, verified_rotation: int | None = None) -> None:
        """Commit an admitted record only against its verified predecessor snapshot."""
        ...

    def observe_head(self, principal: str, head: int, *, authority_revision: int) -> None:
        """Commit the shared recovery/wrap floor only for the verified authority snapshot."""
        ...

    def read_ciphertext(self, principal: str, kind: StoreKind) -> tuple[int, bytes]:
        """Return the generation and serialized slots/rows from one committed read."""
        ...

    def write_verified_ciphertext(self, principal: str, kind: StoreKind, payload: bytes, *,
                                  generation: int, head: int, authority_revision: int) -> None:
        """Fence verified bytes against history, shared floor and store generation atomically."""
        ...

    def read_authority(self) -> tuple[int, dict[str, HistorySnapshot]]:
        """Return every enrolled history and a revision fencing any authority write."""
        ...

    def read(self, principal: str) -> HistorySnapshot | None:
        """Read genesis and every admitted entry in a single committed snapshot."""
        ...
