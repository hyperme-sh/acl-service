"""Current ownership to authenticated allocation and atomic source consumption."""
import asyncio
from dataclasses import dataclass
import hashlib
import json

from acl_service.allocation_protocol.media_allocation_grant import AllocationScope, verify_allocation_grant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


@dataclass(frozen=True)
class AllocationBinding:
    tenant: str
    reader: str
    authority: object
    client: object
    signer: object
    issuer: str
    source: str
    policy: dict
    policy_until: int
    issuer_keys: dict

    async def allocate(self, record):
        # Snapshot caller input before the first await or worker handoff.
        try:
            if type(record) is not dict or len(canonical(record))>2048:raise ValueError()
            record=json.loads(canonical(record));policy=json.loads(canonical(self.policy))
        except (ValueError,TypeError,RecursionError):
            raise AdmissionRejected('Invalid allocation ownership') from None
        scope=AllocationScope(self.issuer,self.tenant,record.get('object'),self.reader,self.source,
            hashlib.sha256(canonical(policy)).hexdigest(),hashlib.sha256(canonical(record)).hexdigest())
        try:
            scope.claims()
            async with asyncio.timeout(4):
                def prepare(cancel):
                    return self.authority.prepare_allocation_request(self.tenant,self.reader,record,policy,
                        self.policy_until,sign_request=self.signer,cancel=cancel)
                request=await self.authority._work(prepare)
                raw=await self.client.issue(scope,request)
                def consume(cancel):
                    return self.authority.consume_allocation(self.tenant,self.reader,record,policy,self.policy_until,
                        verify_grant=lambda at:verify_allocation_grant(raw,expected=scope,keys=self.issuer_keys,now=at),
                        cancel=cancel)
                await self.authority._work(consume)
                return {'object':scope.object,'accepted':True}
        except asyncio.CancelledError:
            raise
        except HistoryConflict:
            raise
        except Exception:
            raise AdmissionRejected('Media allocation refused; reconcile') from None
