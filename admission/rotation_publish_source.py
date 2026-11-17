"""Guarded wallet-rotation append and exact public-record lookup."""
import copy
import hashlib
import json
import re
import time
from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource, encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


class RotationPublishSource:
    def __init__(self, store, *, policy_at, clock=time.time):
        if not store.require_authority_checkpoint or not store.has_freshness:
            raise ValueError('protected rotation source required')
        self.store, self.policy_at, self.clock = store, policy_at, clock

    def _authority(self, principal, cancel):
        at = int(self.clock())
        policy = copy.deepcopy(self.policy_at(at))
        if principal not in policy['activePrincipals']:
            raise AdmissionRejected('rotation owner unavailable')
        def guard():
            cancel()
            if int(self.clock()) != at or self.policy_at(at) != policy:
                raise HistoryConflict('rotation authority changed')
        guard()
        native = HistoryAdmission(self.store, grant_for=lambda _:None,
                                  trust_at=lambda _:policy['trust'], clock=self.clock)
        return at, native, guard

    def publish_wallet_rotation(self, principal, record, *, cancel=lambda:None):
        raw = encoded(record)
        if len(raw) > 65536:
            raise AdmissionRejected('rotation record too large')
        value = _record(raw)
        if (value.get('principal') != principal or value.get('kind') != 'rotate'
                or not isinstance(value.get('authorizer'), dict)
                or value['authorizer'].get('kind') != 'wallet'
                or not isinstance(value.get('attest'), str) or not value['attest']):
            raise AdmissionRejected('signed wallet rotation required')
        _, native, guard = self._authority(principal, cancel)
        # Native admission checks current revocations, wallet ownership, complete
        # histories and authority revision before the guarded atomic append.
        native.admit(principal, raw, before_commit=guard)
        guard()
        return {'recordHash':hashlib.sha256(raw).hexdigest()}

    def wallet_rotation_state(self, principal, record_hash, *, cancel=lambda:None):
        if not isinstance(record_hash, str) or re.fullmatch('[0-9a-f]{64}', record_hash) is None:
            raise AdmissionRejected('invalid rotation hash')
        at, native, guard = self._authority(principal, cancel)
        with self.store._transaction(write=True, before_commit=guard) as db:
            guard()
            accounts = StatementSource._accounts(self, db)
            account = accounts.get(principal)
            if account is None:
                raise AdmissionRejected('unknown rotation owner')
            records = [_record(row) for row in account.entries]
            head = json.loads(native._run_verifier(principal, at, observe=True,
                genesis=_record(account.genesis), entries=records, peers=_peer_inputs(principal, accounts)))
            if (set(head) != {'currentKey','currentEpub','sequence','diagnostics'} or head['diagnostics']
                    or type(head['sequence']) is not int or not 0 <= head['sequence'] <= 9007199254740991):
                raise AdmissionRejected('invalid rotation history')
            self.store._observe_floor(db, principal, head['sequence'])
            present = any(row.get('kind') == 'rotate' and isinstance(row.get('authorizer'), dict)
                and row['authorizer'].get('kind') == 'wallet'
                and hashlib.sha256(encoded(row)).hexdigest() == record_hash for row in records)
            guard()
        guard()
        return {'recordHash':record_hash,'present':present,
                'head':{key:head[key] for key in ('sequence','currentKey','currentEpub')}}
