"""Source-lock admission units with substituted journal and signature verifier."""
import base64
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock

import unittest

from contact_source import ContactSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
def ContactDocument(revision, nonce, payload):
    return SimpleNamespace(revision=revision,nonce=nonce,payload=payload)


def source():
    at = [100]
    db = object()
    @contextmanager
    def transaction(*, write, before_commit):
        yield db
        before_commit()
    result = object.__new__(ContactSource)
    result.tenant = 'tenant'
    result.clock = lambda: at[0]
    result.store = SimpleNamespace(_transaction=transaction)
    result.journal = Mock()
    result.journal.read.return_value = None
    result.journal.write.return_value = ContactDocument(1,b'n'*32,b'x'*28)
    result._fence = Mock(return_value='ef'*32)
    result._verify = Mock(return_value={'currentKey':'owner-key'})
    return result, at


class ContactSourceTests(unittest.TestCase):
    def test_private_state_requires_same_authenticated_owner(self):
        s, _ = source()
        with self.assertRaises(AdmissionRejected): s.read('tenant','other','owner','vault',100)
        with self.assertRaises(AdmissionRejected): s.write('tenant','other','owner','vault',100,0,b'x'*28,'sig','ef'*32)
        with self.assertRaises(AdmissionRejected): s.read('other','owner','owner','vault',100)
        s.journal.read.assert_not_called()
        s._verify.assert_not_called()


    def test_descriptor_read_authenticates_both_viewer_and_owner(self):
        s, _ = source()
        result = s.read('tenant','reader','owner','descriptor',100)
        assert result['revision']==0 and result['payload'] is None
        assert [c.args[1] for c in s._verify.call_args_list]==['reader','owner']


    def test_write_checks_revision_before_crypto_and_commits_verified_bytes(self):
        s, _ = source()
        with self.assertRaises(HistoryConflict): s.write('tenant','owner','owner','vault',100,1,b'x'*28,'sig','ef'*32)
        s._verify.assert_not_called()
        s.journal.write.assert_not_called()
        result=s.write('tenant','owner','owner','vault',100,0,b'x'*28,'sig','ef'*32)
        assert result['revision']==1
        assert s._verify.call_args.kwargs['payload']==base64.b64encode(b'x'*28).decode()
        assert s.journal.write.call_args.args[-1]==b'x'*28


    def test_refused_signature_never_reaches_journal_write(self):
        s, _ = source()
        s._verify.side_effect=AdmissionRejected('bad signature')
        with self.assertRaises(AdmissionRejected): s.write('tenant','owner','owner','vault',100,0,b'x'*28,'sig','ef'*32)
        s.journal.write.assert_not_called()


    def test_clock_change_at_commit_aborts_and_no_response_is_returned(self):
        s, at = source()
        def changed(*args, **kwargs):
            at[0]+=1
            return ContactDocument(1,b'n'*32,b'x'*28)
        s.journal.write.side_effect=changed
        with self.assertRaises(HistoryConflict): s.write('tenant','owner','owner','vault',100,0,b'x'*28,'sig','ef'*32)

    def test_configuration_authenticates_reader_and_pins_source_scope(self):
        s, _ = source()
        s.store.source='source'
        s.trust_at=lambda at: {'jwks':{'keys':[]},'policy':{},'pinnedIss':[]}
        result=s.configuration('tenant','owner',100)
        self.assertEqual(result['principal'],'owner')
        self.assertEqual(result['currentKey'],'owner-key')
        self.assertEqual(result['source'],'source')
        with self.assertRaises(AdmissionRejected):s.configuration('wrong','owner',100)

    def test_changed_authority_fence_refuses_even_unchanged_document_revision(self):
        s, _ = source()
        with self.assertRaises(HistoryConflict):
            s.write('tenant','owner','owner','vault',100,0,b'x'*28,'sig','ab'*32)
        s._verify.assert_not_called()
        s.journal.write.assert_not_called()
