"""One-use authenticated challenge consumption, independent of persistence."""
from typing import Protocol


class CheckpointReplayStore(Protocol):
    def consume(self, request_hash: str, consumed_at: int, *, timeout_ms: int) -> None:
        """Atomically consume once and return only after durable commit.

        Reject duplicates, unavailable storage and uncertain commits. Never expire,
        refund or reset consumption after signing/delivery failure. Bound storage
        waits by timeout_ms; callers still enforce enrollment freshness. Operational
        rollback protection remains required independently of this interface.
        """
        ...
