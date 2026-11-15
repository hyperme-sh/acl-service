"""Protected independent group key history; no plaintext keys or media grants."""
import hashlib
import hmac
import json

from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.infrastructure.epoch_verifier import GroupEpochConfigVerifier
from acl_service.infrastructure.group_epoch_verifier import GroupEpochVerifier

MAX_SAFE = 9007199254740991


class GroupKeySource:
    def __init__(self, source):
        self.source, self.media, self.store, self.journal = source, source.media, source.store, source.journal
        self.native = GroupEpochVerifier()
        self.configs = GroupEpochConfigVerifier()

    def _load(self, db, tenant, writer, at, predicate, set_id):
        self.media._group_key(predicate, set_id)
        if tenant != self.media.tenant:
            raise AdmissionRejected('wrong group tenant')
        held = self.journal.read(db, predicate, set_id)
        if held is None:
            raise AdmissionRejected('group unavailable')
        document = json.loads(held.document)
        if at >= document['policyUntil']:
            raise AdmissionRejected('group policy expired')
        current = self.source._cohort(db, document['policy'], at, predicate, set_id, document['rows'])
        cohort, bindings = current['cohort'], current['bindings']
        owner = cohort['setOwner']
        if writer != owner:
            raise AdmissionRejected('group owner required')
        owner_binding = bindings[owner]
        snapshot = {'predicate': predicate, 'setId': set_id, 'setOwner': owner,
            'ownerSigningPub': owner_binding['pub'], 'ownerEncryptionPub': owner_binding['epub'],
            'ownerIdentityHead': owner_binding['head'], 'members': [
                {**member, 'signingPub': bindings[member['accessor']]['pub'],
                 'encryptionPub': bindings[member['accessor']]['epub'],
                 'identityHead': bindings[member['accessor']]['head']}
                for member in cohort['members']]}
        config = document['configs'][-1]
        expected = {'owner': owner, 'ownerPub': owner_binding['pub'], 'predicate': predicate,
            'setId': set_id, 'settleWindowMs': config['settleWindowMs'],
            'configRevision': config['configRevision']}
        if not self.configs.matches_config(encoded(config), encoded(expected)):
            raise AdmissionRejected('current group policy signature required')
        return held, document, snapshot, config

    def _fence(self, db, held, at, predicate, set_id):
        message = encoded(['group-key-v1', self.media.tenant, predicate, set_id, at,
            held.revision, hashlib.sha256(held.document).hexdigest(), authority_digest(db).hex()])
        return hmac.new(held.nonce, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _parent(document):
        if not document['epochs']:
            return 0, ''
        proof = document['epochs'][-1]['finalization']['proof']
        return proof['epoch'], proof['finalizationId']

    @staticmethod
    def _history(document, snapshot, config, at):
        epochs = document['epochs']
        proof = epochs[-1]['finalization']['proof']
        return {'object': snapshot['setId'], 'current': snapshot, 'config': config,
            'manifests': [{'document': row['document'], 'expected': row['expected']} for row in epochs],
            'finalizations': [row['finalization'] for row in epochs], 'nowMs': at * 1000,
            'anchorFinalizationId': epochs[0]['finalization']['proof']['finalizationId'],
            'minimumEpoch': proof['epoch'], 'expectedEpoch': proof['epoch'],
            'expectedRevisionId': proof['revisionId']}

    def view(self, tenant, writer, at, predicate, set_id, cancel=lambda: None):
        self.media._guard(at, cancel)
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, document, snapshot, config = self._load(db, tenant, writer, at, predicate, set_id)
            previous, parent = self._parent(document)
            if previous >= MAX_SAFE or len(document['epochs']) >= 64:
                raise AdmissionRejected('group epoch capacity')
            return {'at': at, 'fence': self._fence(db, held, at, predicate, set_id),
                'snapshot': snapshot, 'config': config, 'previousEpoch': previous,
                'previousFinalizationId': parent}

    @staticmethod
    def _command(command):
        if type(command) is not dict or set(command) != {'document', 'finalization'} or len(encoded(command)) > 65536:
            raise AdmissionRejected('invalid group epoch command')
        command = json.loads(encoded(command))
        document, proof = command['document'], command['finalization']
        if type(document) is not dict or set(document) != {'manifest', 'snapshot'} or type(document['manifest']) is not dict or type(proof) is not dict:
            raise AdmissionRejected('invalid group epoch document')
        return command

    def append(self, tenant, writer, at, predicate, set_id, fence, command, cancel=lambda: None):
        self.media._guard(at, cancel)
        command = self._command(command)
        with self.store._transaction(write=True, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, document, snapshot, config = self._load(db, tenant, writer, at, predicate, set_id)
            if type(fence) is not str or not hmac.compare_digest(fence, self._fence(db, held, at, predicate, set_id)):
                raise HistoryConflict('group key authority changed')
            if any(row['document'] == command['document'] and row['finalization']['proof'] == command['finalization'] for row in document['epochs']):
                return True
            previous, parent = self._parent(document)
            manifest, proof = command['document']['manifest'], command['finalization']
            if previous >= MAX_SAFE or len(document['epochs']) >= 64:
                raise AdmissionRejected('group epoch capacity')
            if (command['document']['snapshot'] != snapshot or
                    manifest.get('previousEpoch') != previous or manifest.get('epoch') != previous + 1 or
                    manifest.get('settleWindowMs') != config['settleWindowMs'] or
                    proof.get('previousEpoch') != previous or proof.get('epoch') != previous + 1 or
                    proof.get('previousFinalizationId') != parent or
                    proof.get('revisionId') != manifest.get('revisionId') or
                    proof.get('candidateRevisionIds') != [manifest.get('revisionId')]):
                raise AdmissionRejected('group epoch is not the current successor')
            expected = {'object': set_id, 'ownerPub': snapshot['ownerSigningPub'],
                'epoch': previous + 1, 'revisionId': manifest.get('revisionId')}
            if not self.native.matches_manifest(encoded(command['document']), encoded(expected)):
                raise AdmissionRejected('group epoch signature refused')
            document['epochs'].append({'document': command['document'], 'expected': expected,
                'finalization': {'proof': proof, 'ownerPub': snapshot['ownerSigningPub'], 'seenAt': at * 1000}})
            if not self.native.verifies_history(encoded(self._history(document, snapshot, config, at))):
                raise AdmissionRejected('group epoch history refused')
            # Preserve space and revisions for every retained assent withdrawal.
            reserved = self.media._group_withdrawal_capacity({'group': document['rows']})
            if held.revision + 1 + reserved > MAX_SAFE or len(encoded(document)) - len(encoded(document['rows'])) + 512 * 1024 > 4 * 1024 * 1024:
                raise AdmissionRejected('group withdrawal capacity')
            self.journal.write(db, predicate, set_id, held, document)
        return True

    def state(self, tenant, writer, at, predicate, set_id, command, cancel=lambda: None):
        self.media._guard(at, cancel)
        command = self._command(command)
        with self.store._transaction(write=False, before_commit=lambda: self.media._guard(at, cancel)) as db:
            held, document, _, _ = self._load(db, tenant, writer, at, predicate, set_id)
            applied = any(row['document'] == command['document'] and row['finalization']['proof'] == command['finalization'] for row in document['epochs'])
            return {'at': at, 'state': 'applied' if applied else 'absent',
                'fence': self._fence(db, held, at, predicate, set_id)}
