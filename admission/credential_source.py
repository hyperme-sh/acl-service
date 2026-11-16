"""Whole-domain credential lookup over already protected identity history."""
import json
import time
from uuid import UUID
from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource, encoded, MAX_BYTES
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest


class CredentialSource:
    """No DDL or enrollment. The configured domain is the entire source store.

    Completeness is limited to identities enrolled under exclusive admission
    from genesis in this domain. This is not a claim about arbitrary external
    records or another tenant. The authenticated binding chooses the domain.
    """
    def __init__(self, store, tenant, source, *, policy_at, clock=time.time, verifier=None):
        self.store, self.clock = store, clock
        self.tenant, self.source = str(UUID(tenant)), str(UUID(source))
        if self.tenant != tenant or self.source != source or not UUID(tenant).int or not UUID(source).int:
            raise ValueError('canonical authority domain required')
        if getattr(store, 'tenant', None) != tenant or getattr(store, 'source', None) != source:
            raise ValueError('foreign authority store')
        if not store.require_authority_checkpoint:
            raise ValueError('protected authority required')
        self.policy_at = policy_at
        self.production_ready = verifier is None
        self.verifier = verifier or self._verify

    def _guard(self, at, cancel):
        if type(at) is not int or at < 0 or at != int(self.clock()):
            raise HistoryConflict('credential evaluation expired')
        cancel()

    def _verify(self, accounts, credential, at, policy):
        principal = next(iter(accounts)); account = accounts[principal]
        verifier = HistoryAdmission(self.store, grant_for=lambda _: None,
            trust_at=lambda _: policy['trust'], clock=self.clock)
        return json.loads(verifier._run_verifier(principal, at, genesis=_record(account.genesis),
            entries=[_record(row) for row in account.entries], peers=_peer_inputs(principal, accounts),
            credentialLookup=credential))

    def read(self, credential, at, cancel=lambda: None):
        self._guard(at, cancel)
        policy = self.policy_at(at)
        def guard():
            self._guard(at, cancel)
            if self.policy_at(at) != policy:
                raise HistoryConflict('credential policy changed')
        guard()
        credential = json.loads(encoded(credential))
        if len(encoded(credential)) > 4096:
            raise AdmissionRejected('credential capacity')
        # Same lock and checkpoint as all admission/recovery writes. No second
        # index, pagination, caller principal filter or mutable completeness flag.
        with self.store._transaction(write=True, before_commit=guard) as db:
            accounts = StatementSource._accounts(self, db)
            result = self.verifier(accounts, credential, at, policy)
            guard()
            if set(result) != {'snapshot', 'heads'} or set(result['heads']) != set(accounts):
                raise AdmissionRejected('incomplete authority result')
            snapshot = result['snapshot']
            if snapshot['completeThrough'] != at or snapshot['credential'] != credential:
                raise AdmissionRejected('foreign credential result')
            for principal, head in result['heads'].items():
                if type(head) is not int or head < 0:
                    raise AdmissionRejected('invalid authority head')
                self.store._observe_floor(db, principal, head)
            result = {'version':1, 'tenant':self.tenant, 'source':self.source,
                      'authorityDigest':authority_digest(db).hex(), 'snapshot':snapshot, 'trust':policy['trust']}
            if len(encoded(result)) > MAX_BYTES:
                raise AdmissionRejected('credential result capacity')
        guard()
        return result
