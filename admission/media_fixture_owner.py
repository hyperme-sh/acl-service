"""Additive enrollment of the declared media fixture in the canonical TEST source."""
from dataclasses import dataclass
import re
import time

from acl_service.domain.history_store import AdmissionRejected
from first_media_owner import DECLARED_WALLET
from history_admission import HistoryAdmission, _record

TENANT = 'afee9b29-1706-5590-bbbf-e58df8945ac0'
SOURCE = '98f35fce-a5c1-59e6-b874-dd6410b5b531'
SEA_KEY = re.compile(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}')


@dataclass(frozen=True)
class TestMediaOwnerGrant:
    principal: str
    wallet: str
    nonce: str
    expires_at: int

    @property
    def authority(self):
        return f's3rch-test-media-owner-v1:{TENANT}:{SOURCE}:{self.wallet}'


def admit_test_media_owner(store, grant, genesis, signature, *, resolve, trust_at, clock=time.time):
    """Resolve the fixture and current grant through the owning TEST configuration.

    The resolver returns the exact current grant and the already admitted
    operator principal. The native signature binds this fixture to the existing
    TEST source. The operator cannot be selected as the fixture.
    """
    now = int(clock())
    if (type(grant) is not TestMediaOwnerGrant or store.tenant != TENANT or store.source != SOURCE
            or not isinstance(grant.principal, str) or SEA_KEY.fullmatch(grant.principal) is None
            or not isinstance(grant.wallet, str) or re.fullmatch(r'0x[0-9a-f]{40}', grant.wallet) is None
            or grant.wallet == DECLARED_WALLET or not isinstance(grant.nonce, str)
            or re.fullmatch(r'[a-f0-9]{64}', grant.nonce) is None or type(grant.expires_at) is not int
            or not now < grant.expires_at <= now + 60):
        raise AdmissionRejected('invalid TEST media owner grant')
    operator = None

    def current():
        nonlocal operator
        resolved = resolve(TENANT, SOURCE)
        at = int(clock())
        if (not isinstance(resolved, tuple) or len(resolved) != 2 or resolved[0] != grant
                or not isinstance(resolved[1], str) or SEA_KEY.fullmatch(resolved[1]) is None
                or resolved[1] == grant.principal or (operator is not None and operator != resolved[1])
                or not now <= at < grant.expires_at):
            raise AdmissionRejected('TEST media owner grant unavailable or changed')
        operator = resolved[1]

    current()
    admission = HistoryAdmission(store, grant_for=lambda _: None, trust_at=trust_at, clock=clock)
    signed = {'principal': grant.principal, 'authority': grant.authority,
              'nonce': grant.nonce, 'expires_at': grant.expires_at}
    if admission._verify(grant.principal, now, genesis=_record(genesis), entries=[],
                         grant=signed, signature=signature) != b'accepted':
        raise AdmissionRejected('TEST media owner signature refused')
    current()
    return store.enroll_media_fixture(operator, grant.principal, genesis, before_commit=current)
