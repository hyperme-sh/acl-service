"""Release private wrap bytes only after the owner source commits its fence."""
import asyncio
from dataclasses import dataclass
import hashlib
import re
import time
from typing import Protocol


class WrapDeliveryRejected(ValueError):
    pass


@dataclass(frozen=True)
class WrapReadPermit:
    tenant: str
    reader: str
    object: str
    record: str
    digest: str
    epoch: int
    revision_id: str
    reader_epub: str
    fence: str
    expires_at: int


@dataclass(frozen=True)
class DeliveredWrap:
    """Only the committed consumer context; no storage location or owner fence."""
    payload: bytes
    object: str
    epoch: int
    revision_id: str
    reader_epub: str
    expires_at: int


class WrapAuthority(Protocol):
    async def authorize_read(self, tenant: str, reader: str, object: str) -> WrapReadPermit:
        """Current Check, enrolled reader binding, epoch and private record.

        Resolve all values from one protected view. The fence covers identity,
        ACL/cancellation, group policy, epoch/item head, wrap digest and recipient
        key state. Neither login nor storage possession establishes this grant.
        """
        ...

    async def commit_delivery(self, permit: WrapReadPermit) -> bool:
        """Atomically revalidate the complete fence and commit retained floors.

        Return exactly True only after the transaction commits. A concurrent
        identity/ACL/policy/item/key change or stale rollback checkpoint refuses.
        """
        ...


async def deliver_private_wrap_context(authority: WrapAuthority, store, tenant: str, reader: str,
                         object: str, *, clock=time.time, cancel=lambda: None) -> DeliveredWrap:
    """A trusted internal operation; the public transport must authenticate reader.

    The owner source is mandatory. No implementation or default permissive source
    is installed by this module. Provider or source errors never return material.
    """
    try:
        async with asyncio.timeout(3.0):
            cancel()
            if store.tenant != tenant:
                raise ValueError()
            permit = await authority.authorize_read(tenant, reader, object)
            if type(permit) is not WrapReadPermit or (permit.tenant, permit.reader, permit.object) != (tenant, reader, object):
                raise ValueError()
            if any(type(value) is not str or re.fullmatch(r'[0-9a-f]{64}',value) is None
                   for value in (permit.record,permit.digest,permit.revision_id,permit.fence)):
                raise ValueError()
            if (type(permit.epoch) is not int or not 0 <= permit.epoch <= 9_007_199_254_740_991
                    or type(permit.expires_at) is not int or not clock() < permit.expires_at
                    or type(permit.reader_epub) is not str or not 0 < len(permit.reader_epub) <= 1024):
                raise ValueError()
            payload = await store.read(permit.record,permit.digest,cancel=cancel)
            cancel()
            if (type(payload) is not bytes or not 0 < len(payload) <= 65_536
                    or hashlib.sha256(payload).hexdigest() != permit.digest
                    or not clock() < permit.expires_at):
                raise ValueError()
            # Fetching bytes is not authorization. This is the delivery linearization
            # point, after storage has returned and against the exact immutable permit.
            if await authority.commit_delivery(permit) is not True:
                raise ValueError()
            cancel()
            if not clock() < permit.expires_at:
                raise ValueError()
            return DeliveredWrap(payload, permit.object, permit.epoch, permit.revision_id,
                                 permit.reader_epub, permit.expires_at)
    except Exception:
        raise WrapDeliveryRejected('private wrap delivery refused') from None


async def deliver_private_wrap(authority: WrapAuthority, store, tenant: str, reader: str,
                         object: str, *, clock=time.time, cancel=lambda: None) -> bytes:
    """Compatibility adapter for internal consumers needing only the bytes."""
    result = await deliver_private_wrap_context(authority, store, tenant, reader, object,
                                               clock=clock, cancel=cancel)
    return result.payload
