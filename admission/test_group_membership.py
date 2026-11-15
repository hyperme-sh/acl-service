from contextlib import contextmanager
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from group_membership import GroupMembership, MAX_REVISION
from media_source import MediaSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


class GroupMembershipContracts(TestCase):
    def setUp(self):
        self.media = Mock(tenant='tenant')
        for name in ('_group_key', '_group_candidate', '_group_withdrawal_capacity'):
            setattr(self.media, name, getattr(MediaSource, name))
        self.db = object()
        self.store, self.journal = Mock(), Mock()
        @contextmanager
        def transaction(*, write, before_commit):
            yield self.db
            before_commit()
        self.store._transaction.side_effect = transaction
        self.doc = {'policy': {}, 'policyUntil': 1000, 'rows': []}
        self.held = SimpleNamespace(revision=1, nonce=b'n'*32, document=json.dumps(self.doc).encode())
        self.journal.read.return_value = self.held
        self.source = GroupMembership(SimpleNamespace(media=self.media, store=self.store, journal=self.journal))
        self.current = {'memberPub':'member-key','ownerPub':'owner-key','state':{
            'predicate':'same-group','set':'set_a','member':'member','setOwner':'owner',
            'memberAssent':None,'setAssent':None,'cancels':[],'stated':0}}
        self.project = patch.object(self.source, '_state', return_value=self.current).start()
        patch('group_membership.authority_digest',return_value=b'authority').start()
        self.addCleanup(patch.stopall)
        self.args = ('tenant','owner',100,'same-group','set_a','member','set')

    def row(self, view):
        return {'kind':'membership','soul':'membership-soul','record':{**view['draft'],'sig':'signed'}}

    def test_owner_invitation_is_signed_preparation_and_member_cannot_self_invite(self):
        view=self.source.view(*self.args,1)
        self.assertEqual(view['signerPub'],'owner-key')
        self.assertEqual(view['draft']['hamState'],1)
        row=self.row(view)
        self.assertTrue(self.source.append(*self.args,view['fence'],row))
        self.assertEqual(self.journal.write.call_args.args[4]['rows'],[row])
        with self.assertRaises(AdmissionRejected):
            self.source.view('tenant','member',100,'same-group','set_a','member','member',1)
        with self.assertRaises(AdmissionRejected):
            self.source.view('tenant','member',100,'same-group','set_a','member','set',1)

    def test_member_acceptance_and_same_ham_withdrawal_after_invitation_removal(self):
        state=self.current['state'];state['setAssent']={'stated':1,'hamState':4,'cancels':[]}
        args=('tenant','member',100,'same-group','set_a','member','member')
        accepted=self.source.view(*args,1)
        self.assertEqual(accepted['draft']['hamState'],5)
        self.assertEqual(accepted['signerPub'],'member-key')
        state['memberAssent']={'stated':1,'hamState':MAX_REVISION,'cancels':[]}
        state['setAssent']=None
        withdrawn=self.source.view(*args,0)
        self.assertEqual(withdrawn['draft']['hamState'],MAX_REVISION)
        self.assertEqual(withdrawn['draft']['cancels'],[])
        self.assertTrue(self.source.append(*args,withdrawn['fence'],self.row(withdrawn)))

    def test_exact_reconciliation_and_duplicate_write_do_not_append(self):
        view=self.source.view(*self.args,1);row=self.row(view)
        self.assertEqual(self.source.state(*self.args,row)['state'],'absent')
        self.doc['rows']=[row];self.held.document=json.dumps(self.doc).encode()
        current=self.source.state(*self.args,row)
        self.assertEqual(current['state'],'applied')
        self.assertTrue(self.source.append(*self.args,current['fence'],row))
        self.journal.write.assert_not_called()

    def test_signature_scope_expiry_fence_and_draft_changes_refuse(self):
        view=self.source.view(*self.args,1);row=self.row(view)
        for changed in ({**row,'record':{**row['record'],'issuedAt':95}},
                        {**row,'record':{**row['record'],'hamState':3}},
                        {**row,'record':{**row['record'],'role':'member'}}, {},
                        {**row,'record':[]}, {**row,'soul':'x'*9000}):
            with self.assertRaises(AdmissionRejected):self.source.append(*self.args,view['fence'],changed)
        with self.assertRaises(HistoryConflict):self.source.append(*self.args,'wrong',row)
        self.project.side_effect=AdmissionRejected('forged')
        with self.assertRaises(AdmissionRejected):self.source.append(*self.args,view['fence'],row)
        self.journal.write.assert_not_called()

    def test_unavailable_wrong_owner_and_expired_policy_refuse(self):
        with self.assertRaises(AdmissionRejected):self.source.view('wrong',*self.args[1:],1)
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args[:-1],'bad',1)
        self.journal.read.return_value=None
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,1)
        self.journal.read.return_value=self.held
        self.doc['policyUntil']=100;self.held.document=json.dumps(self.doc).encode()
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,1)

    def test_order_and_cancellation_refusals_preserve_withdrawal(self):
        state=self.current['state']
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,0)
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,True)
        state['cancels']=['c']*65
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,1)
        state['cancels']=[];state['setAssent']={'stated':1,'hamState':MAX_REVISION,'cancels':[]}
        with self.assertRaises(AdmissionRejected):self.source.view(*self.args,1)
        self.assertEqual(self.source.view(*self.args,0)['draft']['hamState'],MAX_REVISION)

    def test_positive_history_and_revision_limits_keep_removal_available(self):
        view=self.source.view(*self.args,1)
        self.doc['rows']=[self.row({'draft':{**view['draft'],'hamState':n+1}}) for n in range(8)]
        self.held.document=json.dumps(self.doc).encode()
        self.current['state']['setAssent']={'stated':1,'hamState':8,'cancels':[]}
        view=self.source.view(*self.args,1)
        with self.assertRaisesRegex(AdmissionRejected,'history exhausted'):
            self.source.append(*self.args,view['fence'],self.row(view))
        removal=self.source.view(*self.args,0)
        self.assertTrue(self.source.append(*self.args,removal['fence'],self.row(removal)))
        self.held.revision=MAX_REVISION
        with self.assertRaisesRegex(AdmissionRejected,'revision capacity'):
            self.source.append(*self.args,self.source.view(*self.args,0)['fence'],self.row(removal))
        self.held.revision=1
        self.doc['padding']='x'*(4*1024*1024)
        self.held.document=json.dumps(self.doc).encode()
        with self.assertRaisesRegex(AdmissionRejected,'document capacity'):
            self.source.append(*self.args,self.source.view(*self.args,0)['fence'],self.row(removal))

    def test_reconciliation_rejects_another_role_and_native_input_is_scoped(self):
        view=self.source.view(*self.args,1);row=self.row(view)
        with self.assertRaises(AdmissionRejected):
            self.source.state(*self.args,{**row,'record':{**row['record'],'member':'other'}})
        self.media._accounts.return_value={'owner':SimpleNamespace(genesis=b'{}',entries=())}
        with patch('group_membership.HistoryAdmission') as runner, patch('group_membership._peer_inputs',return_value=[]):
            runner.return_value._run_verifier.return_value=json.dumps(self.current)
            actual=GroupMembership._state(self.source,self.db,self.doc,100,'same-group','set_a','member',[])
            self.assertEqual(actual,self.current)
            self.assertEqual(runner.return_value._run_verifier.call_args.kwargs['groupMemberStateGraph'],{
                'predicate':'same-group','set':'set_a','member':'member','rows':[]})
            self.assertEqual(runner.call_args.kwargs['trust_at']('ignored'),{})
            self.assertIsNone(runner.call_args.kwargs['grant_for']('ignored'))
