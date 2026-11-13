"""Private byte publication requires a durable reservation and a current commit."""
import asyncio
from dataclasses import dataclass
import hashlib
import time
from acl_service.domain.history_store import HistoryConflict


@dataclass(frozen=True)
class WrapWritePermit:
    tenant: str
    owner: str
    object: str
    record: str
    digest: str
    length: int
    fence: str
    expires_at: int


class WrapPublicationRejected(ValueError):
    pass


async def publish_private_wrap(authority, store, tenant, owner, object, at, fence, metadata, payload, *, clock=time.time):
    """No unreserved uploads, automatic signature retries, or quota release."""
    if type(payload) is not bytes or not 0 < len(payload) <= 65536 or store.tenant != tenant:
        raise WrapPublicationRejected('private wrap publication refused')
    digest = hashlib.sha256(payload).hexdigest()
    try:
        async with asyncio.timeout(4.0):
            permit = await authority.prepare_wrap_write(tenant, owner, object, at, fence, metadata, digest, len(payload))
            if (type(permit) is not WrapWritePermit or permit.tenant != tenant or permit.owner != owner
                    or permit.object != object or permit.record != digest or permit.digest != digest
                    or permit.length != len(payload) or type(permit.expires_at) is not int
                    or not clock() < permit.expires_at <= clock()+3):
                raise ValueError()
            if await store.create_or_reconcile(permit.record, payload) != digest:
                raise ValueError()
            if clock() >= permit.expires_at:
                raise ValueError()
            if await authority.commit_wrap_write(permit) is not True:
                raise ValueError()
            if clock() >= permit.expires_at:
                raise ValueError()
            return digest
    except asyncio.CancelledError:
        raise
    except HistoryConflict:
        raise
    except Exception:
        raise WrapPublicationRejected('private wrap publication refused') from None
