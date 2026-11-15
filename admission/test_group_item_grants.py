"""Mock-only protected group item grant admission units."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from group_item_grants import GroupItemGrants,grant_key,reserve,version_reserve,MAX_SAFE
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict


class GroupItemGrantTests(TestCase):
    def setUp(self):
        self.db=object();self.row=(1,b'n'*32,b'raw');self.doc={'objectVersion':1,'policyUntil':5000,'grants':[{'direct':'untouched'}],
            'wraps':{'owner':{'itemDigest':'d'*64}}}
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner-key'},'reader':{'pub':'reader-key'}}}
        @contextmanager
        def transaction(*,write,before_commit):
            yield self.db;before_commit()
        self.store=SimpleNamespace(_transaction=transaction)
        self.media=Mock(tenant='tenant',clock=lambda:100,native=[Mock()])
        self.media.native[0].matches_grant.return_value=True
        self.media._load.side_effect=lambda *a:(self.row,deepcopy(self.doc))
        self.media.identities.return_value=self.ids;self.media._fence.return_value='media-fence'
        self.media._save.side_effect=lambda db,obj,row,doc:setattr(self,'doc',deepcopy(doc))
        self.media._permit.side_effect=lambda *a:(SimpleNamespace(epoch=2,fence='item-fence'),self.ids,self.row,deepcopy(self.doc))
        self.members=[{'accessor':'owner','stated':1},{'accessor':'reader','stated':1}]
        self.current=({'policyUntil':5000},{'members':self.members},{'settleWindowMs':3600000})
        self.view={'projection':{'predicate':'same-group','set':'set'},'fence':'joint-fence'}
        self.items=SimpleNamespace(media=self.media,store=self.store,_authority=Mock(side_effect=lambda *a:(self.view,self.row,deepcopy(self.doc),self.ids,self.current)))
        self.source=GroupItemGrants(self.items)

    def view_grant(self,withdraw=False,**changes):
        values=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set',reader='reader',withdraw=withdraw)
        values.update(changes);return self.source.view(**values)

    def append(self,view=None,**changes):
        view=view or self.view_grant()
        values=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set',at=view['at'],
            fence=view['fence'],payload={'claims':view['grant'],'proof':{'signature':'signed'}})
        values.update(changes);return self.source.append(**values)

    def test_grants_remain_separate_and_cancel_after_membership_is_lost(self):
        view=self.view_grant();self.assertEqual(view['grant'],{'object':'media','accessor':'reader','from':100000,'until':5000000,
            'stated':1,'epoch':3,'owner':'owner','grantRevision':1,'itemCiphertextDigest':'d'*64})
        self.assertTrue(self.append(view));self.assertEqual(self.doc['grants'],[{'direct':'untouched'}])
        self.assertEqual(version_reserve(self.doc),2)
        before=deepcopy(self.doc);self.assertTrue(self.append(view));self.assertEqual(self.doc,before)
        self.items._authority.side_effect=AdmissionRejected('withdrawn')
        cancelled=self.view_grant(True)
        self.assertEqual(cancelled['grant'],{**view['grant'],'stated':0,'grantRevision':2})
        self.assertTrue(self.append(cancelled));self.assertEqual(version_reserve(self.doc),1)
        self.assertTrue(self.append(view));self.assertEqual(self.doc['groupItemGrants']['rows'][-1]['claims']['stated'],0)
        with self.assertRaises(AdmissionRejected):self.view_grant(True)

    def test_current_recipient_owner_scope_and_fence_are_mandatory(self):
        for change in [{'tenant':'other'},{'owner':'other'},{'reader':[]},{'withdraw':1}]:
            with self.assertRaises(AdmissionRejected):self.view_grant(**change)
        for members in [[],[{'accessor':'reader','stated':0}],[{'accessor':'reader','stated':1}]*2]:
            self.members[:]=members
            with self.assertRaises(AdmissionRejected):self.view_grant()
        self.members[:]=[{'accessor':'reader','stated':1}]
        with self.assertRaises(AdmissionRejected):self.view_grant(reader='unknown')
        self.view['projection']['set']='other'
        with self.assertRaises(AdmissionRejected):self.view_grant()
        self.view['projection']['set']='set';self.current=None
        with self.assertRaises(AdmissionRejected):self.view_grant()
        self.current=({'policyUntil':5000},{'members':self.members},{'settleWindowMs':3600000})
        view=self.view_grant()
        with self.assertRaises(HistoryConflict):self.append(view,fence='wrong')
        self.view['fence']='changed'
        with self.assertRaises(HistoryConflict):self.append(view)
        self.media._save.assert_not_called()

    def test_signed_same_revision_fork_is_permanent_and_not_a_direct_fork(self):
        view=self.view_grant();self.append(view)
        changed={'claims':{**view['grant'],'until':view['grant']['until']-1},'proof':{'signature':'signed'}}
        with self.assertRaisesRegex(AdmissionRejected,'fork frozen'):self.append(view,payload=changed)
        self.assertEqual(self.doc['groupItemGrants']['frozen'],[grant_key('same-group','set','reader')])
        self.assertEqual(len(self.doc['groupItemGrants']['conflicts']),1)
        self.assertEqual(version_reserve(self.doc),0)
        self.assertNotIn('frozen',self.doc)
        with self.assertRaises(AdmissionRejected):self.view_grant()
        with self.assertRaises(AdmissionRejected):self.append(view)

    def test_claim_shape_signature_and_draft_changes_refuse(self):
        view=self.view_grant();claims=view['grant']
        for payload in [None,{}, {'claims':claims,'proof':'x'*4097},*[{'proof':{},'claims':{**claims,**change}} for change in
            [{'object':'other'},{'owner':'other'},{'accessor':[]},{'accessor':''},{'stated':True},{'stated':2},
             {'epoch':0},{'grantRevision':0},{'until':0},{'from':-1},{'from':MAX_SAFE+1},{'itemCiphertextDigest':'bad'},{'extra':1}]]]:
            with self.assertRaises(AdmissionRejected):self.append(view,payload=payload)
        self.media.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.append(view)
        self.media.native[0].matches_grant.return_value=True
        with self.assertRaises(HistoryConflict):self.append(view,payload={'claims':{**claims,'epoch':4},'proof':{}})
        self.media._save.assert_not_called()

    def test_exhausted_revision_epoch_policy_and_version_refuse(self):
        view=self.view_grant();self.append(view)
        self.doc['groupItemGrants']['rows'][0]['claims']['grantRevision']=MAX_SAFE
        with self.assertRaises(AdmissionRejected):self.view_grant()
        self.doc.pop('groupItemGrants');self.doc['objectVersion']=MAX_SAFE
        with self.assertRaises(AdmissionRejected):self.append(view)
        self.doc['objectVersion']=1
        self.media._permit.side_effect=lambda *a:(SimpleNamespace(epoch=MAX_SAFE,fence='f'),self.ids,self.row,self.doc)
        with self.assertRaises(AdmissionRejected):self.view_grant()
        self.media._permit.side_effect=lambda *a:(SimpleNamespace(epoch=2,fence='f'),self.ids,self.row,self.doc)
        self.current[0]['policyUntil']=100
        with self.assertRaises(AdmissionRejected):self.view_grant()

    def test_capacity_reserves_cancellation_and_fork_space(self):
        view=self.view_grant();self.append(view)
        row=deepcopy(self.doc['groupItemGrants']['rows'][0])
        self.doc['groupItemGrants']['rows']=[{**row,'claims':{**row['claims'],'grantRevision':i+1}} for i in range(64)]
        with self.assertRaises(AdmissionRejected):self.append()
        self.assertGreater(reserve(self.doc),0)
        cancel=self.view_grant(True);self.append(cancel)
        for field in ['conflicts','rows']:
            bad=deepcopy(self.doc)
            bad['groupItemGrants'][field]=([row]*65 if field=='conflicts' else [{**row,'claims':{**row['claims'],'stated':0}}]*65)
            with self.assertRaises(AdmissionRejected):reserve(bad)
        bad=deepcopy(self.doc);bad['groupItemGrants']['padding']='x'*(1024*1024)
        with self.assertRaises(AdmissionRejected):reserve(bad)


    def test_exact_retention_can_be_reconciled_after_expiry_or_owner_rotation(self):
        view=self.view_grant();payload={'claims':view['grant'],'proof':{'signature':'signed'}}
        state=lambda:self.source.state('tenant','owner','media','same-group','set',payload)
        self.assertEqual(state(),{'at':100,'state':'absent','frozen':False})
        self.append(view);self.media.clock=lambda:200
        self.ids['bindings']['owner']['pub']='rotated'
        self.media.native[0].matches_grant.return_value=False
        self.assertEqual(state(),{'at':200,'state':'applied','frozen':False})
        self.doc['groupItemGrants']['frozen'].append(grant_key('same-group','set','reader'))
        self.assertTrue(state()['frozen'])
        payload['proof']={'signature':'altered'}
        with self.assertRaises(AdmissionRejected):state()
        self.media.native[0].matches_grant.return_value=True
        self.assertEqual(state()['state'],'applied')
        payload['claims']={**payload['claims'],'grantRevision':2}
        self.assertEqual(state()['state'],'absent')
