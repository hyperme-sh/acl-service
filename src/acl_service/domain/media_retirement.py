"""Bind protected deletion commands to the configured storage signing domain."""
import asyncio
from dataclasses import dataclass

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


@dataclass(frozen=True)
class RetirementBinding:
    tenant: str
    reader: str
    authority: object
    signer: object

    async def prepare(self, object):
        """Return a short-lived transport command only after source admission."""
        if type(object) is not str or not 1<=len(object)<=256:
            raise AdmissionRejected('Invalid retirement object')
        def sign(authorized):
            if (type(authorized) is not dict or set(authorized)!=
                    {'tenant','object','owner','command','issuedAt','expiresAt'}
                    or authorized['tenant']!=self.tenant or authorized['object']!=object
                    or authorized['owner']!=self.reader or self.signer.tenant!=self.tenant
                    or type(authorized['issuedAt']) is not int or type(authorized['expiresAt']) is not int
                    or authorized['expiresAt']!=authorized['issuedAt']+30):
                raise AdmissionRejected('Protected retirement scope mismatch')
            return self.signer.sign(object=object,owner=self.reader,command=authorized['command'],now=authorized['issuedAt'])
        try:
            async with asyncio.timeout(4):
                def prepare(cancel):
                    return self.authority.prepare_retirement_request(self.tenant,self.reader,object,
                        sign_request=sign,cancel=cancel)
                return await self.authority._work(prepare)
        except asyncio.CancelledError:
            raise
        except HistoryConflict:
            raise
        except Exception:
            raise AdmissionRejected('Media retirement preparation refused') from None
