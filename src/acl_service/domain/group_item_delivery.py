"""Release an item wrap only after joint item and group authority commits."""
import asyncio
from dataclasses import dataclass
import hashlib
import re
import time
from acl_service.domain.group_wrap import GroupKeyReadPermit
from acl_service.domain.history_store import HistoryConflict
from acl_service.domain.private_wrap_delivery import bind_wrap_store


@dataclass(frozen=True)
class GroupItemReadPermit:
    key: GroupKeyReadPermit
    object: str
    item_epoch: int
    item_revision_id: str
    item_digest: str
    wrap_digest: str
    length: int
    fence: str
    expires_at: int


@dataclass(frozen=True)
class DeliveredGroupItemWrap:
    payload: bytes
    object: str
    predicate: str
    set_id: str
    item_epoch: int
    item_revision_id: str
    item_digest: str
    group_epoch: int
    group_revision_id: str
    group_key_commitment: str
    expires_at: int


class GroupItemDeliveryRejected(ValueError):
    pass


async def deliver_group_item_wrap(authority,store,tenant,reader,object,predicate,set_id,*,clock=time.time,cancel=lambda:None):
    """No default authority or HTTP installation. The source must check current
    membership, item grant/status/epoch and both checkpoints in one transaction,
    then recheck that complete authority after storage returns. Group key access
    alone is insufficient. Item wraps use the media object's storage allocation.
    """
    try:
        async with asyncio.timeout(3):
            cancel()
            if store.tenant!=tenant:raise ValueError()
            permit=await authority.authorize_group_item_read(tenant,reader,object,predicate,set_id)
            if type(permit) is not GroupItemReadPermit or type(permit.key) is not GroupKeyReadPermit:raise ValueError()
            key=permit.key
            if ((key.tenant,key.reader,key.predicate,key.set_id,permit.object)!=(tenant,reader,predicate,set_id,object) or
                    type(permit.length) is not int or not 1<=permit.length<=65536 or
                    any(type(epoch) is not int or not 1<=epoch<=9007199254740991 for epoch in (key.epoch,permit.item_epoch)) or
                    type(permit.expires_at) is not int or type(key.expires_at) is not int or
                    not clock()<permit.expires_at<=key.expires_at<=clock()+2 or
                    any(type(value) is not str or re.fullmatch('[a-f0-9]{64}',value) is None for value in
                        (key.revision_id,key.key_commitment,key.fence,permit.item_revision_id,permit.item_digest,permit.wrap_digest,permit.fence))):raise ValueError()
            payload=await bind_wrap_store(store,object).read(permit.wrap_digest,permit.wrap_digest,cancel=cancel)
            cancel()
            if (type(payload) is not bytes or len(payload)!=permit.length or
                    hashlib.sha256(payload).hexdigest()!=permit.wrap_digest or clock()>=permit.expires_at):raise ValueError()
            if await authority.commit_group_item_read(permit) is not True:raise ValueError()
            cancel()
            if clock()>=permit.expires_at:raise ValueError()
            return DeliveredGroupItemWrap(payload,object,predicate,set_id,permit.item_epoch,permit.item_revision_id,
                permit.item_digest,key.epoch,key.revision_id,key.key_commitment,permit.expires_at)
    except HistoryConflict:
        raise
    except Exception:
        raise GroupItemDeliveryRejected('group item delivery refused') from None
