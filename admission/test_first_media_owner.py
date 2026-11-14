"""First-owner admission contracts, including native signatures, run in CI only."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
from unittest import TestCase
from unittest.mock import Mock, patch

from first_media_owner import FirstMediaOwnerGrant, DECLARED_WALLET, admit_first_media_owner
from history_admission import AdmissionRejected


class FirstOwnerTests(TestCase):
    def setUp(self):
        self.f=json.loads(Path(__file__).with_name('fixture.json').read_bytes())
        self.now=self.f['now'];self.principal=self.f['genesis']
        self.grant=FirstMediaOwnerGrant('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',self.principal,'a'*64,self.now+60)
        self.store=Mock(tenant=self.grant.tenant,source=self.grant.source)
        self.resolve=Mock(return_value=self.principal)
        self.store.enroll_first_media_owner.side_effect=lambda *a,**kw:kw['before_commit']()
        self.genesis=json.dumps(self.f['binding']).encode()
        self.signature=json.loads(subprocess.check_output(['node',Path(__file__).with_name('first-owner-fixture.mjs')],input=json.dumps({'authority':self.grant.authority,'nonce':self.grant.nonce,'expires_at':self.grant.expires_at}).encode()))

    def admit(self,grant=None,**kwargs):
        return admit_first_media_owner(self.store,grant or self.grant,self.genesis,kwargs.pop('signature',self.signature),
            resolve_owner=self.resolve,trust_at=lambda _: {k:self.f[k] for k in ('policy','jwks','pinnedIss')},clock=lambda:self.now,**kwargs)

    def test_existing_key_signs_source_bound_first_admission(self):
        self.admit()
        self.store.enroll_first_media_owner.assert_called_once()
        self.assertEqual(self.store.enroll_first_media_owner.call_args.args,(self.principal,self.genesis))
        self.resolve.assert_called_with(DECLARED_WALLET,self.grant.tenant)
        self.assertEqual(self.resolve.call_count,3)

    def test_missing_ambiguous_or_changed_resolution_never_commits(self):
        for value in (None,[],[self.principal],self.principal+'x'):
            self.resolve.return_value=value
            with self.assertRaises(AdmissionRejected):self.admit()
        self.store.enroll_first_media_owner.assert_not_called()
        self.resolve.side_effect=[self.principal,self.principal,None]
        with self.assertRaises(AdmissionRejected):self.admit()

    def test_native_signature_and_scope_binding(self):
        for changes in ({'nonce':'b'*64},{'expires_at':self.now+59}):
            with self.assertRaises(AdmissionRejected):self.admit(replace(self.grant,**changes))
        with self.assertRaises(AdmissionRejected):self.admit(signature='bad')
        self.store.enroll_first_media_owner.assert_not_called()

    def test_resolver_elapsed_time_is_checked_after_resolution(self):
        initial=self.now
        for after in (initial-1,self.grant.expires_at):
            self.now=initial
            def resolve(*args):self.now=after;return self.principal
            self.resolve.side_effect=resolve
            with self.assertRaises(AdmissionRejected):self.admit()
        self.store.enroll_first_media_owner.assert_not_called()

    def test_invalid_grants_expiry_and_clock_regression(self):
        for grant in [object(),replace(self.grant,tenant='bad'),replace(self.grant,source='00000000-0000-0000-0000-000000000003'),
            replace(self.grant,principal='bad'),replace(self.grant,nonce='bad'),replace(self.grant,expires_at=True),
            replace(self.grant,expires_at=self.now),replace(self.grant,expires_at=self.now+61)]:
            with self.assertRaises(AdmissionRejected):self.admit(grant)
        with patch('first_media_owner.HistoryAdmission._verify',return_value=b'fork'):
            with self.assertRaises(AdmissionRejected):self.admit()
        def expired(*args,**kwargs):self.now=self.grant.expires_at;return b'accepted'
        with patch('first_media_owner.HistoryAdmission._verify',side_effect=expired):
            with self.assertRaises(AdmissionRejected):self.admit()
        self.store.enroll_first_media_owner.assert_not_called()
