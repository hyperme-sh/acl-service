"""Read-only transfer authority over the existing checkpointed identity source."""
import hashlib
import json
import time
from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource, encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest


class DeviceTransferSource:
    _accounts = StatementSource._accounts
    _guard = StatementSource._guard

    def __init__(self, store, policy_at, *, clock=time.time):
        if not store.require_authority_checkpoint:
            raise AdmissionRejected('transfer requires protected checkpoints')
        self.store, self.tenant, self.policy_at, self.clock = store, store.tenant, policy_at, clock

    def read(self, principal, scope, identity, binding=None, expected_revision=None, cancel=lambda: None):
        at = int(self.clock())
        policy = self.policy_at(at)
        def guard():
            self._guard(at, cancel)
            if self.policy_at(at) != policy:
                raise HistoryConflict('transfer policy changed')
        guard()
        if scope['tenant'] != self.tenant or scope not in policy['scopes'] or principal not in policy['activePrincipals'] or identity['principal'] != principal:
            raise AdmissionRejected('transfer scope refused')
        with self.store._transaction(write=False, before_commit=guard) as db:
            accounts = self._accounts(db)
            account = accounts.get(principal)
            if account is None:
                raise AdmissionRejected('transfer principal refused')
            runner = HistoryAdmission(self.store, grant_for=lambda _: None,
                trust_at=lambda _: policy['trust'], clock=self.clock)
            state = json.loads(runner._run_verifier(principal, at, deviceTransfer=True,
                genesis=_record(account.genesis), entries=[_record(row) for row in account.entries],
                peers=_peer_inputs(principal, accounts)))
            if state['identity'] != identity:
                raise AdmissionRejected('transfer identity changed')
            revision = hashlib.sha256(encoded(['acl-device-transfer-v1', self.tenant, self.store.source,
                principal, scope, binding, authority_digest(db).hex(), policy])).hexdigest()
            if expected_revision is not None and revision != expected_revision:
                raise HistoryConflict('transfer checkpoint changed')
            valid_until = min((at + 5) * 1000, policy['until'] * 1000)
            if binding is not None:
                valid_until = min(valid_until, binding['expiresAt'])
                if not at * 1000 < binding['expiresAt'] <= (at + 300) * 1000:
                    raise AdmissionRejected('transfer expired')
            result = dict(state, scope=scope, binding=binding, at=at,
                checkpoint={'revision': revision, 'validUntil': valid_until}, trust=policy['trust'])
            if len(encoded(result)) > 4 * 1024 * 1024:
                raise AdmissionRejected('transfer capacity')
        guard()
        return result
