"""Signed contacts descriptor and encrypted vault admission in one source lock."""
import base64
import hashlib
import json
import time

from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
LIMITS = {'descriptor': (1,8192), 'vault': (28,1024*1024)}


class ContactSource:
    def __init__(self, store, *, trust_at, clock=time.time):
        from acl_service.infrastructure.contact_journal import ContactJournal
        self.store, self.tenant, self.clock = store, store.tenant, clock
        self.trust_at = trust_at
        self.journal = ContactJournal(store)

    _guard = StatementSource._guard
    _accounts = StatementSource._accounts

    def _verify(self, db, owner, at, **operation):
        accounts = self._accounts(db)
        account = accounts.get(owner)
        if account is None:
            raise AdmissionRejected('unknown contact owner')
        runner = HistoryAdmission(self.store, grant_for=lambda _: None,
                                  trust_at=self.trust_at, clock=self.clock)
        result = json.loads(runner._run_verifier(owner, at, genesis=_record(account.genesis),
            entries=[_record(row) for row in account.entries], peers=_peer_inputs(owner, accounts),
            contactDocumentInput=dict(owner=owner, tenant=self.tenant, source=self.store.source, **operation)))
        return result

    def configuration(self, tenant, reader, at, cancel=lambda: None):
        self._guard(at, cancel)
        if tenant != self.tenant:
            raise AdmissionRejected('contact configuration refused')
        with self.store._transaction(write=False, before_commit=lambda: self._guard(at, cancel)) as db:
            head = self._verify(db, reader, at, action='read')
            result = {'at': at, 'tenant': self.tenant, 'source': self.store.source,
                      'principal': reader, 'currentKey': head['currentKey'], 'trust': self.trust_at(at)}
        self._guard(at, cancel)
        return result

    def read(self, tenant, reader, owner, kind, at, cancel=lambda: None):
        self._guard(at, cancel)
        if tenant != self.tenant or kind not in LIMITS or (kind == 'vault' and reader != owner):
            raise AdmissionRejected('contact read refused')
        with self.store._transaction(write=False, before_commit=lambda: self._guard(at, cancel)) as db:
            self._verify(db, reader, at, action='read')
            head = self._verify(db, owner, at, action='read')
            row = self.journal.read(db, owner, kind)
            result = {'at': at, 'owner': owner, 'kind': kind, 'head': head,
                      'revision': row.revision if row else 0,
                      'payload': base64.b64encode(row.payload).decode() if row else None}
        self._guard(at, cancel)
        return result

    def write(self, tenant, writer, owner, kind, at, revision, payload, signature, cancel=lambda: None):
        self._guard(at, cancel)
        if tenant != self.tenant or writer != owner or kind not in LIMITS:
            raise AdmissionRejected('contact write refused')
        if type(revision) is not int or revision < 0 or type(payload) is not bytes:
            raise AdmissionRejected('invalid contact write')
        minimum, maximum = LIMITS[kind]
        if not minimum <= len(payload) <= maximum:
            raise AdmissionRejected('invalid contact payload')
        with self.store._transaction(write=True, before_commit=lambda: self._guard(at, cancel)) as db:
            current = self.journal.read(db, owner, kind)
            if (current.revision if current else 0) != revision:
                raise HistoryConflict('contact revision changed')
            self._verify(db, owner, at, action='write', kind=kind, revision=revision,
                         payload=base64.b64encode(payload).decode(), signature=signature)
            saved = self.journal.write(db, owner, kind, current, payload)
        self._guard(at, cancel)
        return {'at': at, 'revision': saved.revision, 'digest': hashlib.sha256(saved.payload).hexdigest()}
