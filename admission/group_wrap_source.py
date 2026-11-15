"""Protected group wrap metadata and durable publication reservations."""
import hashlib
import hmac
import json
import re
from statement_source import encoded
from group_key_source import GroupKeyReadPermit, MAX_SAFE
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest


from acl_service.domain.group_wrap import GroupWrapWritePermit, GroupWrapReadPermit


class GroupWrapSource:
    def __init__(self, keys):
        self.keys, self.media, self.store, self.journal = keys, keys.media, keys.store, keys.journal

    def _metadata(self, document, snapshot, config, metadata, at):
        fields = {'reader','readerEpub','epoch','revisionId','digest'}
        if type(metadata) is not dict or set(metadata) != fields or len(encoded(metadata)) > 4096:
            raise AdmissionRejected('invalid group wrap metadata')
        if not document.get('allocation') or not document['epochs']:
            raise AdmissionRejected('allocated group key required')
        latest = document['epochs'][-1]['document']['manifest']
        members = [m for m in snapshot['members'] if m['accessor'] == metadata['reader'] and m['stated'] == 1]
        if (len(members) != 1 or metadata['readerEpub'] != members[0]['encryptionPub'] or
                type(metadata['epoch']) is not int or metadata['epoch'] != latest['epoch'] or
                metadata['revisionId'] != latest['revisionId'] or type(metadata['digest']) is not str or
                re.fullmatch('[0-9a-f]{64}',metadata['digest']) is None):
            raise AdmissionRejected('group wrap is not current')
        if not self.keys.native.verifies_history(encoded(self.keys._history(document,snapshot,config,at))):
            raise AdmissionRejected('current group key history required')
        return metadata

    def _save(self, db, predicate, set_id, held, document):
        reserved = self.media._group_withdrawal_capacity({'group':document['rows']})
        if (held.revision + 1 + reserved > MAX_SAFE or
                len(encoded(document)) - len(encoded(document['rows'])) + 512*1024 > 4*1024*1024):
            raise AdmissionRejected('group withdrawal capacity')
        self.journal.write(db,predicate,set_id,held,document)

    def _fence(self, db, held, permit):
        fields = [permit.tenant,permit.owner,permit.predicate,permit.set_id,
                  permit.digest,permit.length,permit.expires_at]
        return hmac.new(held.nonce,encoded(['group-wrap-write-v1',fields,held.revision,
            hashlib.sha256(held.document).hexdigest(),authority_digest(db).hex()]),hashlib.sha256).hexdigest()

    def prepare(self, tenant, owner, predicate, set_id, at, fence, metadata, length, cancel=lambda:None):
        guard = lambda:self.media._guard(at,cancel)
        guard()
        if type(length) is not int or not 1 <= length <= 65536:
            raise AdmissionRejected('invalid group wrap length')
        metadata = json.loads(encoded(metadata))
        with self.store._transaction(write=True,before_commit=guard) as db:
            held,document,snapshot,config = self.keys._load(db,tenant,owner,at,predicate,set_id)
            if type(fence) is not str or not hmac.compare_digest(fence,self.keys._fence(db,held,at,predicate,set_id)):
                raise HistoryConflict('group wrap authority changed')
            self._metadata(document,snapshot,config,metadata,at)
            digest = metadata['digest']
            uploads = document.setdefault('uploads',{})
            reservation = {'metadata':metadata,'length':length}
            if digest in uploads:
                if uploads[digest] != reservation:
                    raise HistoryConflict('group wrap reservation changed')
            else:
                if len(uploads) >= 4096:
                    raise AdmissionRejected('group wrap capacity')
                # Exactly one opaque wrap per epoch/recipient; uncertain writes
                # keep this reservation and must be retried with identical bytes.
                identity = (metadata['epoch'],metadata['revisionId'],metadata['reader'])
                if any((r['metadata']['epoch'],r['metadata']['revisionId'],r['metadata']['reader']) == identity
                       for r in uploads.values()):
                    raise HistoryConflict('group recipient wrap already reserved')
                uploads[digest] = reservation
                self._save(db,predicate,set_id,held,document)
                held = self.journal.read(db,predicate,set_id)
            expires = min(at+3,document['policyUntil'])
            permit = GroupWrapWritePermit(tenant,owner,predicate,set_id,digest,length,'',expires)
            return GroupWrapWritePermit(tenant,owner,predicate,set_id,digest,length,self._fence(db,held,permit),expires)

    def commit(self, permit, cancel=lambda:None):
        at = int(self.media.clock())
        guard = lambda:self.media._guard(at,cancel)
        guard()
        if (type(permit) is not GroupWrapWritePermit or type(permit.expires_at) is not int or
                not at < permit.expires_at <= at+3 or type(permit.fence) is not str):
            raise AdmissionRejected('invalid group wrap permit')
        with self.store._transaction(write=True,before_commit=guard) as db:
            held,document,snapshot,config = self.keys._load(db,permit.tenant,permit.owner,at,permit.predicate,permit.set_id)
            if not hmac.compare_digest(permit.fence,self._fence(db,held,permit)):
                raise HistoryConflict('group wrap publication authority changed')
            reservation = document.get('uploads',{}).get(permit.digest)
            if reservation is None or reservation['length'] != permit.length:
                raise AdmissionRejected('group wrap reservation unavailable')
            metadata = self._metadata(document,snapshot,config,reservation['metadata'],at)
            if metadata in document['wraps']:
                return True
            document['wraps'].append(metadata)
            self._save(db,permit.predicate,permit.set_id,held,document)
        return True

    def _read(self, db, tenant, reader, predicate, set_id, at, expires=None):
        key = self.keys._read_permit(db,tenant,reader,at,predicate,set_id,expires)
        held = self.journal.read(db,predicate,set_id)
        document = json.loads(held.document)
        matches = [m for m in document['wraps'] if m['reader'] == reader and m['epoch'] == key.epoch
                   and m['revisionId'] == key.revision_id and m['readerEpub'] == key.reader_epub]
        if len(matches) != 1:
            raise AdmissionRejected('current group wrap unavailable')
        metadata = matches[0]
        reservation = document.get('uploads',{}).get(metadata['digest'])
        if reservation is None or reservation['metadata'] != metadata:
            raise AdmissionRejected('group wrap reservation unavailable')
        return GroupWrapReadPermit(key,metadata['digest'],reservation['length'])

    def authorize_read(self, tenant, reader, predicate, set_id, cancel=lambda:None):
        at = int(self.media.clock());guard = lambda:self.media._guard(at,cancel)
        guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            return self._read(db,tenant,reader,predicate,set_id,at)

    def commit_read(self, permit, cancel=lambda:None):
        if type(permit) is not GroupWrapReadPermit or type(permit.key) is not GroupKeyReadPermit:
            raise AdmissionRejected('invalid group wrap read permit')
        key = permit.key
        at = int(self.media.clock());guard = lambda:self.media._guard(at,cancel)
        guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            current = self._read(db,key.tenant,key.reader,key.predicate,key.set_id,at,key.expires_at)
            if current != permit:
                raise HistoryConflict('group wrap delivery authority changed')
        return True
