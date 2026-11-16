"""Release an item wrap only after joint item and group authority commits."""
import asyncio
from dataclasses import dataclass
import hashlib
import re
import time
from acl_service.domain.group_wrap import GroupKeyReadPermit
from acl_service.domain.history_store import HistoryConflict


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


def _item_store_binding(store):
    # Group-item bytes belong to the media allocation, never a generic record store.
    bind=getattr(type(store),'for_object',None)
    if not callable(bind):raise ValueError('item allocation store required')
    return bind


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
            bind=_item_store_binding(store)
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
            payload=await bind(store,object).read(permit.wrap_digest,permit.wrap_digest,cancel=cancel)
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


@dataclass(frozen=True)
class GroupItemWritePermit:
    tenant: str
    owner: str
    object: str
    predicate: str
    set_id: str
    reader: str
    digest: str
    length: int
    fence: str
    expires_at: int


async def publish_group_item_wrap(authority,store,tenant,owner,object,predicate,set_id,reader,at,fence,metadata,payload,*,clock=time.time):
    """Reserve exact opaque bytes, publish to the item allocation, then commit."""
    import json
    try:
        if type(payload) is not bytes or not 1<=len(payload)<=65536 or store.tenant!=tenant:raise ValueError()
        bind=_item_store_binding(store)
        digest=hashlib.sha256(payload).hexdigest()
        if type(metadata) is not dict or metadata.get('digest')!=digest:raise ValueError()
        metadata=json.loads(json.dumps(metadata,allow_nan=False))
        async with asyncio.timeout(4):
            permit=await authority.prepare_group_item_write(tenant,owner,object,predicate,set_id,reader,at,fence,metadata,len(payload))
            if (type(permit) is not GroupItemWritePermit or
                    (permit.tenant,permit.owner,permit.object,permit.predicate,permit.set_id,permit.reader,permit.digest,permit.length)!=
                    (tenant,owner,object,predicate,set_id,reader,digest,len(payload)) or
                    type(permit.length) is not int or type(permit.expires_at) is not int or
                    not clock()<permit.expires_at<=clock()+2 or type(permit.fence) is not str or
                    re.fullmatch('[a-f0-9]{64}',permit.fence) is None):raise ValueError()
            if await bind(store,object).create_or_reconcile(digest,payload)!=digest:raise ValueError()
            if clock()>=permit.expires_at:raise ValueError()
            if await authority.commit_group_item_write(permit) is not True:raise ValueError()
            if clock()>=permit.expires_at:raise ValueError()
            return digest
    except HistoryConflict:
        raise
    except Exception:
        raise GroupItemDeliveryRejected('group item publication refused') from None
