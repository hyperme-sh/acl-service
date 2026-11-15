"""Owner-authorized creation of independent groups; no grants or key delivery."""
import hashlib
import hmac
import json

from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.epoch_verifier import GroupEpochConfigVerifier


class GroupSource:
    def __init__(self, media, *, transaction=None):
        from acl_service.infrastructure.group_media_journal import GroupMediaJournal
        self.media = media
        self.store = media.store
        self.journal = GroupMediaJournal(self.store, transaction=transaction)

    def _cohort(self, db, policy, at, predicate, set_id, rows):
        accounts = self.media._accounts(db)
        principal = next(iter(accounts))
        account = accounts[principal]
        runner = HistoryAdmission(self.store, grant_for=lambda _: None,
                                  trust_at=lambda _: policy, clock=self.media.clock)
        return json.loads(runner._run_verifier(principal, at,
            genesis=_record(account.genesis), entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal, accounts),
            groupCohortGraph={'predicate': predicate, 'set': set_id, 'rows': rows}))

    def _creation(self, db, tenant, writer, anchor, at, predicate, set_id):
        self.media._group_key(predicate, set_id)
        if tenant != self.media.tenant:
            raise AdmissionRejected('wrong group tenant')
        held, document = self.media._load(db, anchor, at)
        if writer != self.media.identities(db, anchor, document, at)['owner']:
            raise AdmissionRejected('group creation requires an owned anchor')
        result = self._cohort(db, document['policy'], at, predicate, set_id, [])
        owner = result['cohort']['setOwner']
        if writer != owner:
            raise AdmissionRejected('group set owner required')
        if self.journal.read(db, predicate, set_id) is not None:
            raise HistoryConflict('group already exists')
        context = {'owner': owner, 'ownerPub': result['bindings'][owner]['pub'],
                   'predicate': predicate, 'setId': set_id}
        # The media anchor binds policy and current identity history. The group
        # scope is additionally bound so one preparation cannot create another.
        fence = hashlib.sha256(encoded(['group-create-v1', predicate, set_id,
            self.media._fence(db, anchor, held, at)])).hexdigest()
        return document, context, fence

    def creation_view(self, tenant, writer, anchor, at, predicate, set_id, cancel=lambda: None):
        self.media._guard(at, cancel)
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            _, context, fence = self._creation(db, tenant, writer, anchor, at, predicate, set_id)
            return {'at': at, 'context': context, 'fence': fence}

    def create(self, tenant, writer, anchor, at, predicate, set_id, fence, config, cancel=lambda: None):
        self.media._guard(at, cancel)
        self.media._group_policy_shape(config)
        config = json.loads(encoded(config))
        with self.store._transaction(write=True, before_commit=lambda: self.media._guard(at, cancel)) as db:
            document, context, current = self._creation(db, tenant, writer, anchor, at, predicate, set_id)
            if type(fence) is not str or not hmac.compare_digest(fence, current):
                raise HistoryConflict('group creation authority changed')
            expected = {**context, 'settleWindowMs': config['settleWindowMs'], 'configRevision': config['configRevision']}
            if not GroupEpochConfigVerifier().matches_config(encoded(config), encoded(expected)):
                raise AdmissionRejected('group creation signature refused')
            self.journal.write(db, predicate, set_id, None, {
                'policy': document['policy'], 'policyUntil': document['policyUntil'],
                'configs': [config], 'rows': [], 'epochs': [], 'wraps': [],
            })
        return True

    def creation_state(self, tenant, writer, anchor, at, predicate, set_id, config, cancel=lambda: None):
        """Reconcile the exact signed creation without replacing retained state."""
        self.media._guard(at, cancel)
        self.media._group_key(predicate, set_id)
        self.media._group_policy_shape(config)
        config = json.loads(encoded(config))
        if tenant != self.media.tenant:
            raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held = self.journal.read(db, predicate, set_id)
            if held is None:
                _, _, fence = self._creation(db, tenant, writer, anchor, at, predicate, set_id)
                return {'at': at, 'state': 'absent', 'fence': fence}
            document = json.loads(held.document)
            if at >= document['policyUntil']:
                raise AdmissionRejected('group policy expired')
            current = self._cohort(db, document['policy'], at, predicate, set_id, document['rows'])
            if writer != current['cohort']['setOwner']:
                raise AdmissionRejected('group set owner required')
            # A later owner rotation does not erase an already admitted command.
            # This only confirms retention, never membership or key delivery.
            if config not in document['configs']:
                raise HistoryConflict('different group creation retained')
            return {'at': at, 'state': 'applied'}
