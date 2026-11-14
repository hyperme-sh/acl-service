"""Explicit first admission of an existing key into a new protected source."""
from dataclasses import dataclass
import re
import time
from uuid import UUID

from acl_service.domain.history_store import AdmissionRejected
from history_admission import HistoryAdmission, _record

DECLARED_WALLET='0x4c8d36f87287e75d3d84f1aed72655eccbc7a1a7'


@dataclass(frozen=True)
class FirstMediaOwnerGrant:
    tenant: str
    source: str
    principal: str
    nonce: str
    expires_at: int

    @property
    def authority(self):
        return f's3rch-first-media-owner-v1:{self.tenant}:{self.source}:{DECLARED_WALLET}'


def admit_first_media_owner(store, grant, genesis, signature, *, resolve_owner, trust_at, clock=time.time):
    """Operator-only; resolve_owner must use the trusted unique wallet resolver.

    A public export or a caller claim is not this resolver. None/ambiguous results
    refuse. This creates no key and imports no prior ACL journal.
    """
    if type(grant) is not FirstMediaOwnerGrant:
        raise AdmissionRejected('first owner grant required')
    try:
        if any(str(UUID(value))!=value or not UUID(value).int for value in (grant.tenant,grant.source)):
            raise ValueError()
    except (ValueError,TypeError,AttributeError):
        raise AdmissionRejected('invalid first owner scope') from None
    now=int(clock())
    if (grant.tenant!=store.tenant or grant.source!=store.source
            or type(grant.principal) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}',grant.principal)
            or type(grant.nonce) is not str or not re.fullmatch(r'[a-f0-9]{64}',grant.nonce)
            or type(grant.expires_at) is not int or not now<grant.expires_at<=now+60):
        raise AdmissionRejected('invalid first owner grant')
    def current():
        resolved=resolve_owner(DECLARED_WALLET,grant.tenant)
        at=int(clock())
        if at<now or at>=grant.expires_at or resolved!=grant.principal:
            raise AdmissionRejected('first owner resolution changed or unavailable')
    current()
    admission=HistoryAdmission(store,grant_for=lambda _:None,trust_at=trust_at,clock=clock)
    signed={'principal':grant.principal,'authority':grant.authority,'nonce':grant.nonce,'expires_at':grant.expires_at}
    if admission._verify(grant.principal,now,genesis=_record(genesis),entries=[],grant=signed,signature=signature)!=b'accepted':
        raise AdmissionRejected('first owner signature refused')
    current()
    store.enroll_first_media_owner(grant.principal,genesis,before_commit=current)
