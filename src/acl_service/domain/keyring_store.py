"""Backend-neutral keyring storage contract for already verified operations.

Only a trusted verifier may call mutations after authenticating the principal,
complete fresh history, signatures, predecessor hashes and envelope semantics.
Storage does not grant authority or verify cryptography. Payloads are serialized
ciphertext, never plaintext keys.

Both stores and the history floor serialize together per principal. Successful
returns represent committed state. A stale generation rejects ciphertext but
commits a newer verified floor. A stale head changes nothing. Empty ciphertext
retains generation/floor tombstones. An ambiguous commit requires re-reading and
re-verifying/re-signing; implementations must not blindly retry a signed write.
"""
from dataclasses import dataclass
from typing import Literal, Protocol

MAX_GENERATION = 9_007_199_254_740_991
StoreKind = Literal["recovery", "wraps"]


class StoreRejected(ValueError):
    def __init__(self) -> None:
        super().__init__("store-rejected")


@dataclass(frozen=True)
class KeyringState:
    head_floor: int
    recovery_generation: int
    wrap_generation: int
    recovery: bytes
    wraps: bytes


class KeyringStore(Protocol):
    def read_state(self, principal: str) -> KeyringState | None:
        """Read one committed snapshot; absence is not account-creation authority."""
        ...

    def observe_verified_head(self, principal: str, head: int) -> KeyringState:
        """Commit a verified nondecreasing history floor before returning."""
        ...

    def compare_and_swap_verified(
        self, principal: str, *, head: int, kind: StoreKind,
        expected_generation: int, payload: bytes,
    ) -> KeyringState:
        """Commit one verified transition, or raise StoreRejected on conflict."""
        ...
