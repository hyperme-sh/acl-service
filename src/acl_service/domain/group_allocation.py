"""Protected current group ownership to durable allocation and atomic consumption."""
import asyncio
from dataclasses import dataclass

from acl_service.allocation_protocol.group_allocation_grant import GroupAllocationScope, verify_group_allocation_grant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


@dataclass(frozen=True)
class GroupAllocationBinding:
    tenant: str
    reader: str
    authority: object
    client: object
    signer: object
    issuer: str
    source: str
    issuer_keys: dict

    async def allocate(self, record):
        if (type(record) is not dict or set(record) != {'predicate','set'} or
                record['predicate'] not in ('same-group','named-circle') or
                type(record['set']) is not str or not 5 <= len(record['set']) <= 512):
            raise AdmissionRejected('Invalid group allocation scope')
        predicate, set_id = record['predicate'], record['set']
        try:
            async with asyncio.timeout(4):
                def prepare(cancel):
                    scopes=[]
                    def sign(authorized):
                        scope=GroupAllocationScope(self.issuer,self.tenant,set_id,self.reader,self.source,
                            authorized['policyDigest'],authorized['creationDigest'],predicate)
                        scope.claims()
                        if any(authorized.get(k)!=v for k,v in {'tenant':self.tenant,'set':set_id,'owner':self.reader,'predicate':predicate}.items()):
                            raise AdmissionRejected('Group source scope changed')
                        raw=self.signer(authorized)
                        scopes.append(scope)
                        return raw
                    request=self.authority.prepare_group_allocation_request(self.tenant,self.reader,predicate,set_id,
                        sign_request=sign,cancel=cancel)
                    if len(scopes)!=1:
                        raise AdmissionRejected('Group source authorization unavailable')
                    return scopes[0],request
                scope,request=await self.authority._work(prepare)
                raw=await self.client.issue(scope,request)
                await self.authority._work(lambda cancel:self.authority.consume_group_allocation(
                    self.tenant,self.reader,predicate,set_id,
                    verify_grant=lambda at:verify_group_allocation_grant(raw,expected=scope,keys=self.issuer_keys,now=at),
                    cancel=cancel))
                return {'set':set_id,'predicate':predicate,'accepted':True}
        except asyncio.CancelledError:
            raise
        except HistoryConflict:
            raise
        except Exception:
            raise AdmissionRejected('Group allocation refused; reconcile') from None
