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


from acl_service.domain.group_wrap import GroupKeyReadPermit


class GroupKeySource:
    def __init__(self, source):
        self.source, self.media, self.store, self.journal = source, source.media, source.store, source.journal
        self.native = GroupEpochVerifier()
        self.configs = GroupEpochConfigVerifier()

    def _load_current(self, db, tenant, at, predicate, set_id):
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

    def _load(self, db, tenant, writer, at, predicate, set_id):
        result = self._load_current(db, tenant, at, predicate, set_id)
        if writer != result[2]['setOwner']:
            raise AdmissionRejected('group owner required')
        return result

    def _read_permit(self, db, tenant, reader, at, predicate, set_id, expires=None):
        held, document, snapshot, config = self._load_current(db, tenant, at, predicate, set_id)
        members = [member for member in snapshot['members']
                   if member['accessor'] == reader and member['stated'] == 1]
        if len(members) != 1 or not document['epochs'] or not document.get('allocation'):
            raise AdmissionRejected('current allocated group membership required')
        if not self.native.matches_settled(encoded(self._history(document, snapshot, config, at))):
            raise AdmissionRejected('current settled group key required')
        manifest = document['epochs'][-1]['document']['manifest']
        limit = min(at + 2, document['policyUntil'])
        expires = limit if expires is None else expires
        if type(expires) is not int or not at < expires <= limit:
            raise AdmissionRejected('group key permit expired')
        fields = [tenant, reader, predicate, set_id, manifest['epoch'],
                  manifest['revisionId'], members[0]['encryptionPub'], manifest['keyCommitment'], expires]
        fence = hmac.new(held.nonce, encoded(['group-key-read-v1', fields, held.revision,
            hashlib.sha256(held.document).hexdigest(), authority_digest(db).hex()]), hashlib.sha256).hexdigest()
        return GroupKeyReadPermit(*fields[:-1], fence, expires)

    def authorize_key_read(self, tenant, reader, predicate, set_id, cancel=lambda: None):
        at = int(self.media.clock())
        guard = lambda: self.media._guard(at, cancel)
        guard()
        with self.store._transaction(write=False, before_commit=guard) as db:
            return self._read_permit(db, tenant, reader, at, predicate, set_id)

    def commit_key_read(self, permit, cancel=lambda: None):
        if type(permit) is not GroupKeyReadPermit:
            raise AdmissionRejected('invalid group key permit')
        at = int(self.media.clock())
        guard = lambda: self.media._guard(at, cancel)
        guard()
        # The independent group checkpoint covers the complete latest history.
        # Revalidate in the protected write transaction immediately before bytes
        # can be returned; neither owner status nor an older epoch is a fallback.
        with self.store._transaction(write=True, before_commit=guard) as db:
            current = self._read_permit(db, permit.tenant, permit.reader, at,
                permit.predicate, permit.set_id, permit.expires_at)
            if current != permit:
                raise HistoryConflict('group key delivery authority changed')
        return True

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

    def prepare_allocation_request(self, tenant, writer, predicate, set_id, *, sign_request, cancel=lambda: None):
        """Attest current owner authority without changing group or key history."""
        at = int(self.media.clock())
        guard = lambda: self.media._guard(at, cancel)
        guard()
        with self.store._transaction(write=False, before_commit=guard) as db:
            _, document, snapshot, _ = self._load(db, tenant, writer, at, predicate, set_id)
            # Bind the original retained creation, not the changing member cohort
            # or epoch: rotations must not allocate another permanent group.
            creation = encoded(['group-creation-v1', tenant, predicate, set_id, document['configs'][0]])
            request = sign_request({'tenant': tenant, 'set': set_id, 'predicate': predicate,
                'owner': snapshot['setOwner'],
                'policyDigest': hashlib.sha256(encoded(document['policy'])).hexdigest(),
                'creationDigest': hashlib.sha256(creation).hexdigest(),
                'issuedAt': at, 'expiresAt': min(at + 30, document['policyUntil'])})
            if type(request) is not bytes or not 1 <= len(request) <= 4096:
                raise AdmissionRejected('invalid signed group allocation request')
            return request

    def consume_allocation(self, tenant, writer, predicate, set_id, *, verify_grant, cancel=lambda: None):
        """Consume the configured issuer's proof and group binding atomically."""
        from acl_service.infrastructure.group_allocation_journal import GroupAllocationJournal
        at = int(self.media.clock())
        guard = lambda: self.media._guard(at, cancel)
        guard()
        allocations = GroupAllocationJournal(self.store)
        with self.store._transaction(write=True, before_commit=guard) as db:
            held, document, snapshot, _ = self._load(db, tenant, writer, at, predicate, set_id)
            proof = verify_grant(at)
            claims = proof.scope.claims()
            creation = encoded(['group-creation-v1', tenant, predicate, set_id, document['configs'][0]])
            expected = {'tenant': tenant, 'set': set_id, 'predicate': predicate,
                'owner': snapshot['setOwner'], 'source': self.store.source,
                'policyDigest': hashlib.sha256(encoded(document['policy'])).hexdigest(),
                'creationDigest': hashlib.sha256(creation).hexdigest()}
            if any(claims.get(key) != value for key, value in expected.items()):
                raise AdmissionRejected('group allocation scope mismatch')
            if (type(proof.issued_at) is not int or type(proof.expires_at) is not int or
                    not 0 <= proof.issued_at <= at < proof.expires_at or
                    not 0 < proof.expires_at - proof.issued_at <= 300 or
                    proof.expires_at > document['policyUntil']):
                raise AdmissionRejected('group allocation validity refused')
            bound = {'claims': claims, 'allocation': proof.allocation,
                'issuedAt': proof.issued_at, 'expiresAt': proof.expires_at}
            digest = hashlib.sha256(encoded(bound)).digest()
            previous = document.get('allocation')
            if previous is not None and previous != bound:
                raise HistoryConflict('different group allocation retained')
            fresh = allocations.consume(db, proof.allocation, predicate, set_id, digest)
            if fresh != (previous is None):
                raise HistoryConflict('group allocation document mismatch')
            if fresh:
                document['allocation'] = bound
                self.journal.write(db, predicate, set_id, held, document)
        return True

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
