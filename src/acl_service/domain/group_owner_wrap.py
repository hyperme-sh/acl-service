"""Separate owner maintenance capability; never a recipient read grant."""
from dataclasses import dataclass


@dataclass(frozen=True)
class GroupOwnerWrapPermit:
    tenant: str
    owner: str
    object: str
    predicate: str
    set_id: str
    record: str
    digest: str
    epoch: int
    revision_id: str
    reader_epub: str
    key_commitment: str
    item_digest: str
    fence: str
    expires_at: int
