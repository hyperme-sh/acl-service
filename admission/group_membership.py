"""Independent group invitation and member-response commands; no key delivery."""
import hashlib
import hmac
import json

from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest

MAX_REVISION = 9007199254740991


class GroupMembership:
    def __init__(self, source):
        self.source, self.media, self.store, self.journal = source, source.media, source.store, source.journal

    def _state(self, db, document, at, predicate, set_id, member, rows):
        accounts = self.media._accounts(db)
        principal = next(iter(accounts))
        account = accounts[principal]
        runner = HistoryAdmission(self.store, grant_for=lambda _: None,
            trust_at=lambda _: document['policy'], clock=self.media.clock)
        return json.loads(runner._run_verifier(principal, at,
            genesis=_record(account.genesis), entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal, accounts), groupMemberStateGraph={
                'predicate': predicate, 'set': set_id, 'member': member, 'rows': rows}))

    def _load(self, db, tenant, writer, at, predicate, set_id, member, role):
        self.media._group_key(predicate, set_id)
        if tenant != self.media.tenant or role not in ('member', 'set'):
            raise AdmissionRejected('invalid group writer scope')
        held = self.journal.read(db, predicate, set_id)
        if held is None: raise AdmissionRejected('group unavailable')
        document = json.loads(held.document)
        if at >= document['policyUntil']: raise AdmissionRejected('group policy expired')
        current = self._state(db, document, at, predicate, set_id, member, document['rows'])
        if writer != (member if role == 'member' else current['state']['setOwner']):
            raise AdmissionRejected('group signer required')
        return held, document, current

    def _fence(self, db, predicate, set_id, held, at):
        message = encoded(['group-member-v1', self.media.tenant, predicate, set_id, at,
            held.revision, hashlib.sha256(held.document).hexdigest(), authority_digest(db).hex()])
        return hmac.new(held.nonce, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _draft(current, at, role, stated):
        if type(stated) is not int or stated not in (0, 1): raise AdmissionRejected('invalid group assent')
        state = current['state']
        own = state['memberAssent' if role == 'member' else 'setAssent']
        if stated == 0:
            if not own or own['stated'] != 1: raise AdmissionRejected('group assent unavailable')
            ham, cancels = own['hamState'], []
        else:
            invitation = state['setAssent']
            cancels = state['cancels']
            if len(cancels) > 64: raise AdmissionRejected('group cancellation capacity')
            if role == 'member' and (not invitation or invitation['stated'] != 1 or
                    any(value not in invitation['cancels'] for value in cancels)):
                raise AdmissionRejected('group invitation unavailable')
            ham = max((state['memberAssent'] or {}).get('hamState', 0),
                      (state['setAssent'] or {}).get('hamState', 0)) + 1
            if ham > MAX_REVISION: raise AdmissionRejected('group order exhausted')
        return {key: state[key] for key in ('predicate', 'set', 'member', 'setOwner')} | {
            'role': role, 'stated': stated, 'hamState': ham, 'issuedAt': at, 'cancels': cancels}

    def view(self, tenant, writer, at, predicate, set_id, member, role, stated, cancel=lambda: None):
        self.media._guard(at, cancel)
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, _, current = self._load(db, tenant, writer, at, predicate, set_id, member, role)
            return {'at': at, 'draft': self._draft(current, at, role, stated),
                'signerPub': current['memberPub' if role == 'member' else 'ownerPub'],
                'fence': self._fence(db, predicate, set_id, held, at)}

    def append(self, tenant, writer, at, predicate, set_id, member, role, fence, row, cancel=lambda: None):
        self.media._guard(at, cancel)
        row = self._row(row)
        with self.store._transaction(write=True, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, document, current = self._load(db, tenant, writer, at, predicate, set_id, member, role)
            if type(fence) is not str or not hmac.compare_digest(fence, self._fence(db, predicate, set_id, held, at)):
                raise HistoryConflict('group membership changed')
            record = row['record']
            if type(record) is not dict or record.get('role') != role or record.get('member') != member:
                raise AdmissionRejected('wrong group response')
            rows = document['rows']
            candidate = self.media._group_candidate(rows, [row])
            # Verify the exact candidate signature and retained graph first.
            self._state(db, document, at, predicate, set_id, member, candidate)
            if len(candidate) == len(rows): return True
            if type(record.get('issuedAt')) is not int or not 0 <= at-record['issuedAt'] <= 4:
                raise AdmissionRejected('group response expired')
            draft = self._draft(current, record['issuedAt'], role, record.get('stated'))
            if record != {**draft, 'sig': record.get('sig')}:
                raise AdmissionRejected('group response changed')
            if record['stated'] == 1 and sum(1 for item in rows if item['kind'] == 'membership'
                    and item['record']['member'] == member and item['record']['role'] == role and item['record']['stated'] == 1) >= 8:
                raise AdmissionRejected('group response history exhausted')
            reserved = self.media._group_withdrawal_capacity({'group': candidate})
            if held.revision + 1 + reserved > MAX_REVISION:
                raise AdmissionRejected('group withdrawal revision capacity')
            document['rows'] = candidate
            # Reserve the entire bounded membership region against later writes.
            if len(encoded(document)) - len(encoded(candidate)) + 512*1024 > 4*1024*1024:
                raise AdmissionRejected('group withdrawal document capacity')
            self.journal.write(db, predicate, set_id, held, document)
        return True

    @staticmethod
    def _row(row):
        if type(row) is not dict or set(row) != {'kind', 'soul', 'record'} or row['kind'] != 'membership' or len(encoded(row)) > 8192:
            raise AdmissionRejected('invalid group member row')
        return json.loads(encoded(row))

    def state(self, tenant, writer, at, predicate, set_id, member, role, row, cancel=lambda: None):
        self.media._guard(at, cancel)
        row = self._row(row)
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, document, _ = self._load(db, tenant, writer, at, predicate, set_id, member, role)
            if type(row['record']) is not dict or row['record'].get('role') != role or row['record'].get('member') != member:
                raise AdmissionRejected('wrong group response')
            rows = document['rows']
            candidate = self.media._group_candidate(rows, [row])
            self._state(db, document, at, predicate, set_id, member, candidate)
            return {'at': at, 'state': 'applied' if len(candidate) == len(rows) else 'absent',
                'fence': self._fence(db, predicate, set_id, held, at)}
