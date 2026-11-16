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


@dataclass(frozen=True)
class DeliveredOwnerWrap:
    payload: bytes
    object: str
    predicate: str
    set_id: str
    epoch: int
    revision_id: str
    reader_epub: str
    key_commitment: str
    item_digest: str
    expires_at: int


class OwnerWrapRejected(ValueError):
    pass


async def deliver_owner_wrap(authority,store,tenant,owner,object,predicate,set_id,*,clock=None,cancel=lambda:None):
    import asyncio
    import hashlib
    import re
    import time
    from acl_service.domain.history_store import HistoryConflict
    clock=clock or time.time
    try:
        async with asyncio.timeout(3):
            cancel()
            bind=getattr(type(store),'for_object',None)
            if store.tenant!=tenant or not callable(bind):raise ValueError()
            permit=await authority.authorize_group_owner_wrap(tenant,owner,object,predicate,set_id)
            if type(permit) is not GroupOwnerWrapPermit or (permit.tenant,permit.owner,permit.object,permit.predicate,permit.set_id)!=(tenant,owner,object,predicate,set_id):raise ValueError()
            if (type(permit.epoch) is not int or not 1<=permit.epoch<=9007199254740991 or
                    type(permit.expires_at) is not int or not clock()<permit.expires_at<=clock()+2 or
                    type(permit.reader_epub) is not str or not 1<=len(permit.reader_epub)<=1024 or
                    any(type(value) is not str or re.fullmatch('[a-f0-9]{64}',value) is None for value in
                        (permit.record,permit.digest,permit.revision_id,permit.key_commitment,permit.item_digest,permit.fence))):raise ValueError()
            payload=await bind(store,object).read(permit.record,permit.digest,cancel=cancel)
            cancel()
            if type(payload) is not bytes or not 1<=len(payload)<=65536 or hashlib.sha256(payload).hexdigest()!=permit.digest or clock()>=permit.expires_at:raise ValueError()
            if await authority.commit_group_owner_wrap(permit) is not True:raise ValueError()
            cancel()
            if clock()>=permit.expires_at:raise ValueError()
            return DeliveredOwnerWrap(payload,object,predicate,set_id,permit.epoch,permit.revision_id,
                permit.reader_epub,permit.key_commitment,permit.item_digest,permit.expires_at)
    except HistoryConflict:
        raise
    except Exception:
        raise OwnerWrapRejected('owner maintenance wrap refused') from None
