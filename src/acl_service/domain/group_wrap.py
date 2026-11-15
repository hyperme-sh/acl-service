"""Immutable group wrap permits and bounded private delivery coordination."""
import asyncio
from dataclasses import dataclass
import hashlib
import re
import time
from acl_service.domain.history_store import HistoryConflict

@dataclass(frozen=True)
class GroupKeyReadPermit:
    tenant: str
    reader: str
    predicate: str
    set_id: str
    epoch: int
    revision_id: str
    reader_epub: str
    key_commitment: str
    fence: str
    expires_at: int


@dataclass(frozen=True)
class GroupWrapWritePermit:
    tenant: str
    owner: str
    predicate: str
    set_id: str
    digest: str
    length: int
    fence: str
    expires_at: int


@dataclass(frozen=True)
class GroupWrapReadPermit:
    key: GroupKeyReadPermit
    digest: str
    length: int


@dataclass(frozen=True)
class DeliveredGroupWrap:
    payload: bytes
    predicate: str
    set_id: str
    epoch: int
    revision_id: str
    reader_epub: str
    key_commitment: str
    expires_at: int


class GroupWrapRejected(ValueError):
    pass


async def publish_group_wrap(authority,store,tenant,owner,predicate,set_id,at,fence,metadata,payload,*,clock=time.time):
    try:
        if type(payload) is not bytes or not 1<=len(payload)<=65536 or store.tenant!=tenant:
            raise ValueError()
        digest=hashlib.sha256(payload).hexdigest()
        if type(metadata) is not dict or metadata.get('digest')!=digest:raise ValueError()
        # Snapshot caller-owned metadata before awaiting protected work.
        metadata=dict(metadata)
        async with asyncio.timeout(4):
            permit=await authority.prepare_group_wrap_write(tenant,owner,predicate,set_id,at,fence,metadata,len(payload))
            if (type(permit) is not GroupWrapWritePermit or
                    (permit.tenant,permit.owner,permit.predicate,permit.set_id,permit.digest,permit.length)!=(tenant,owner,predicate,set_id,digest,len(payload)) or
                    type(permit.expires_at) is not int or not clock()<permit.expires_at<=clock()+3):raise ValueError()
            if await store.for_group(set_id).create_or_reconcile(digest,payload)!=digest:raise ValueError()
            if clock()>=permit.expires_at:raise ValueError()
            if await authority.commit_group_wrap_write(permit) is not True:raise ValueError()
            if clock()>=permit.expires_at:raise ValueError()
            return digest
    except HistoryConflict:
        raise
    except Exception:
        raise GroupWrapRejected('group wrap publication refused') from None


async def deliver_group_wrap(authority,store,tenant,reader,predicate,set_id,*,clock=time.time,cancel=lambda:None):
    try:
        async with asyncio.timeout(3):
            cancel()
            if store.tenant!=tenant:raise ValueError()
            permit=await authority.authorize_group_wrap_read(tenant,reader,predicate,set_id)
            if type(permit) is not GroupWrapReadPermit or type(permit.key) is not GroupKeyReadPermit:raise ValueError()
            key=permit.key
            if ((key.tenant,key.reader,key.predicate,key.set_id)!=(tenant,reader,predicate,set_id) or
                    type(permit.length) is not int or not 1<=permit.length<=65536 or
                    type(key.epoch) is not int or not 1<=key.epoch<=9007199254740991 or
                    type(key.reader_epub) is not str or not 1<=len(key.reader_epub)<=1024 or
                    type(key.expires_at) is not int or not clock()<key.expires_at<=clock()+2 or
                    any(type(v) is not str or re.fullmatch('[a-f0-9]{64}',v) is None
                        for v in (permit.digest,key.revision_id,key.key_commitment,key.fence))):raise ValueError()
            payload=await store.for_group(set_id).read(permit.digest,permit.digest,cancel=cancel)
            cancel()
            if (type(payload) is not bytes or len(payload)!=permit.length or
                    hashlib.sha256(payload).hexdigest()!=permit.digest or clock()>=key.expires_at):raise ValueError()
            if await authority.commit_group_wrap_read(permit) is not True:raise ValueError()
            cancel()
            if clock()>=key.expires_at:raise ValueError()
            return DeliveredGroupWrap(payload,predicate,set_id,key.epoch,key.revision_id,key.reader_epub,key.key_commitment,key.expires_at)
    except HistoryConflict:
        raise
    except Exception:
        raise GroupWrapRejected('group wrap delivery refused') from None
