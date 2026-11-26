"""Additive enrollment of the declared media fixture in the canonical TEST source."""
from dataclasses import dataclass
import re
import time

from acl_service.domain.history_store import AdmissionRejected
from first_media_owner import DECLARED_WALLET
from history_admission import HistoryAdmission, _record

TENANT = 'afee9b29-1706-5590-bbbf-e58df8945ac0'
SOURCE = '98f35fce-a5c1-59e6-b874-dd6410b5b531'
# Public key of the synthetic startup-nightly Contacts fixture in Infra.
CONTACTS_PRINCIPAL = ('nkEr_c-bs6Ajd8-qBskS_YzwIMI5qmWe7xJO0TYuXMs.'
                      'Xthq9PzemRt9cZWEMIrKf-0SUAopz8T_nHDAYIulH84')
SEA_KEY = re.compile(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}')


@dataclass(frozen=True)
class TestMediaOwnerGrant:
    principal: str
    wallet: str
    nonce: str
    expires_at: int
    initial: bool = False

    @property
    def authority(self):
        scope = f's3rch-test-media-owner-v1:{TENANT}:{SOURCE}:{self.wallet}'
        return scope + ':initial' if self.initial else scope


def admit_test_media_owner(store, grant, genesis, signature, *, resolve, trust_at, clock=time.time):
    """Resolve the fixture and current grant through the owning TEST configuration.

    The resolver returns the current grant and either the admitted operator
    principal for additive enrollment or None for initial synthetic enrollment.
    The native signature binds the fixture, source and enrollment mode.
    """
    now = int(clock())
    if (type(grant) is not TestMediaOwnerGrant or store.tenant != TENANT or store.source != SOURCE
            or not isinstance(grant.principal, str) or SEA_KEY.fullmatch(grant.principal) is None
            or not isinstance(grant.wallet, str) or re.fullmatch(r'0x[0-9a-f]{40}', grant.wallet) is None
            or grant.wallet == DECLARED_WALLET or type(grant.initial) is not bool
            or not isinstance(grant.nonce, str)
            or re.fullmatch(r'[a-f0-9]{64}', grant.nonce) is None or type(grant.expires_at) is not int
            or not now < grant.expires_at <= now + 60):
        raise AdmissionRejected('invalid TEST media owner grant')
    operator = None

    def current():
        nonlocal operator
        resolved = resolve(TENANT, SOURCE)
        at = int(clock())
        if (not isinstance(resolved, tuple) or len(resolved) != 2 or resolved[0] != grant
                or not now <= at < grant.expires_at):
            raise AdmissionRejected('TEST media owner grant unavailable or changed')
        current_operator = resolved[1]
        if grant.initial:
            if current_operator is not None:
                raise AdmissionRejected('initial TEST media owner grant cannot replace an operator')
        elif (not isinstance(current_operator, str) or SEA_KEY.fullmatch(current_operator) is None
                or current_operator == grant.principal or (operator is not None and operator != current_operator)):
            raise AdmissionRejected('TEST media owner operator unavailable or changed')
        operator = current_operator

    current()
    admission = HistoryAdmission(store, grant_for=lambda _: None, trust_at=trust_at, clock=clock)
    signed = {'principal': grant.principal, 'authority': grant.authority,
              'nonce': grant.nonce, 'expires_at': grant.expires_at}
    if admission._verify(grant.principal, now, genesis=_record(genesis), entries=[],
                         grant=signed, signature=signature) != b'accepted':
        raise AdmissionRejected('TEST media owner signature refused')
    current()
    if grant.initial:
        return store.enroll_first_media_owner(grant.principal, genesis, before_commit=current,
                                             allow_exact_retry=True, contacts_principal=CONTACTS_PRINCIPAL)
    return store.enroll_media_fixture(operator, grant.principal, genesis, before_commit=current)
