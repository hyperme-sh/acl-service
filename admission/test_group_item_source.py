"""Mock-only joint item/group protected preparation units."""
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from copy import deepcopy
from group_item_source import GroupItemSource
from acl_service.domain.history_store import AdmissionRejected


class GroupItemSourceTests(TestCase):
    def setUp(self):
        self.db=object();self.guards=[]
        @contextmanager
        def transaction(*,write,before_commit):
            self.assertFalse(write);yield self.db;before_commit()
        store=SimpleNamespace(_transaction=transaction)
        self.item=SimpleNamespace(tenant='tenant',reader='owner',object='media',epoch=2,revision_id='a'*64,fence='i'*64,expires_at=102)
        self.group=SimpleNamespace(tenant='tenant',reader='owner',predicate='same-group',set_id='set',epoch=3,revision_id='b'*64,
                                   key_commitment='c'*64,fence='g'*64,expires_at=102)
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner-key'}}}
        self.row=(1,b'n'*32,b'document');self.document={'wraps':{'owner':{'itemDigest':'d'*64}}}
        self.media=Mock(tenant='tenant',clock=lambda:100)
        self.media._permit.return_value=(self.item,self.ids,self.row,self.document)
        self.keys=SimpleNamespace(media=self.media,store=store,_read_permit=Mock(return_value=self.group))
        self.source=GroupItemSource(self.keys)

    def view(self,**changes):
        args=dict(tenant='tenant',owner='owner',object='media',predicate='same-group',set_id='set');args.update(changes)
        return self.source.view(**args)

    def test_joint_current_context_and_fence(self):
        result=self.view()
        self.media._permit.assert_called_once_with(self.db,'tenant','owner','media',100)
        self.keys._read_permit.assert_called_once_with(self.db,'tenant','owner',100,'same-group','set')
        self.assertEqual(result['item'],{'epoch':2,'revisionId':'a'*64,'digest':'d'*64})
        self.assertEqual(result['group'],{'epoch':3,'revisionId':'b'*64,'keyCommitment':'c'*64})
        self.assertEqual(result['expiresAt'],102)
        self.assertNotIn('readerEpub',result)
        self.group.fence='changed';self.assertNotEqual(result['fence'],self.view()['fence'])
        self.media._guard.assert_called()

    def test_other_tenant_owner_scope_and_expiry_refuse(self):
        with self.assertRaises(AdmissionRejected):self.view(tenant='other')
        self.media._permit.assert_not_called()
        self.ids['owner']='other'
        with self.assertRaises(AdmissionRejected):self.view()
        self.keys._read_permit.assert_not_called();self.ids['owner']='owner'
        self.item.object='other'
        with self.assertRaises(AdmissionRejected):self.view()
        self.item.object='media';self.group.set_id='other'
        with self.assertRaises(AdmissionRejected):self.view()
        self.group.set_id='set'
        for expires in [100,103]:
            self.item.expires_at=self.group.expires_at=expires
            with self.assertRaises(AdmissionRejected):self.view()

    def test_missing_current_item_or_group_never_returns_partial_context(self):
        self.media._permit.side_effect=AdmissionRejected('item changed')
        with self.assertRaises(AdmissionRejected):self.view()
        self.keys._read_permit.assert_not_called()
        self.media._permit.side_effect=None;self.keys._read_permit.side_effect=AdmissionRejected('group changed')
        with self.assertRaises(AdmissionRejected):self.view()

    def authority_setup(self):
        self.edge={'kind':'object-set','record':{'stated':1}}
        self.object_row={'kind':'object','record':{'object':'media'}}
        self.old_member={'kind':'membership','record':{'stated':1,'member':'old'}}
        self.old_cancel={'kind':'cancel','record':{'kind':'membership'}}
        self.edge_cancel={'kind':'cancel','record':{'kind':'object-set'}}
        self.document.update(objectVersion=3,groupScopes={'same-group:set':[
            self.object_row,self.edge,self.old_member,self.old_cancel,self.edge_cancel]})
        self.current_member={'kind':'membership','record':{'stated':0,'member':'old'}}
        self.group_doc={'rows':[self.current_member]}
        self.media._load.return_value=(self.row,self.document)
        self.media.identities.return_value=self.ids
        self.media._fence.return_value='media-fence'
        self.media._group_key=lambda predicate,set_id:predicate+':'+set_id
        self.projection={'object':'media','predicate':'same-group','set':'set','members':[],
                         'snapshot':{'objectSet':{'stated':1}}}
        self.media._group_object_projection.return_value=self.projection
        self.group_snapshot={'members':[{'accessor':'owner','stated':1}]}
        self.keys._load_current=Mock(return_value=('group-held',self.group_doc,self.group_snapshot,{}))
        self.keys._fence=Mock(return_value='group-fence')

    def authority(self,**changes):
        args=dict(tenant='tenant',owner='owner',object='media');args.update(changes)
        return self.source.authority_view(**args)

    def test_authority_joins_current_rows_and_fences_without_mutating_retained_history(self):
        self.authority_setup();original=deepcopy(self.document)
        result=self.authority()
        self.keys._load_current.assert_called_once_with(self.db,'tenant',100,'same-group','set')
        args=self.media._group_object_projection.call_args.args
        self.assertEqual(args[:2],(self.db,'media'))
        self.assertEqual(args[2]['groupScopes']['same-group:set'],[
            self.object_row,self.edge,self.edge_cancel,self.current_member])
        self.assertEqual(self.document,original)
        self.assertEqual(result['projection'],self.projection)
        self.assertEqual(result['ownerPub'],'owner-key')
        self.assertEqual(result['objectVersion'],3)
        self.keys._fence.return_value='withdrawal-fence'
        self.assertNotEqual(result['fence'],self.authority()['fence'])
        self.media._save.assert_not_called()

    def test_authority_never_falls_back_to_copied_members_or_another_owner(self):
        self.authority_setup()
        with self.assertRaises(AdmissionRejected):self.authority(tenant='other')
        self.media._load.assert_not_called()
        with self.assertRaises(AdmissionRejected):self.authority(owner='other')
        self.keys._load_current.assert_not_called()
        self.keys._load_current.side_effect=AdmissionRejected('missing independent group')
        with self.assertRaises(AdmissionRejected):self.authority()
        self.assertEqual(self.media._group_object_projection.call_count,1)
        self.media._save.assert_not_called()

    def test_item_ownership_does_not_disclose_an_unrelated_groups_members(self):
        self.authority_setup()
        for members in [[],[{'accessor':'other','stated':1}],[{'accessor':'owner','stated':0}],
                        [{'accessor':'owner','stated':1}]*2]:
            self.group_snapshot['members']=members
            self.media._group_object_projection.reset_mock()
            with self.assertRaises(AdmissionRejected):self.authority()
            self.assertEqual(self.media._group_object_projection.call_count,1)
            self.assertNotIn(self.current_member,self.media._group_object_projection.call_args.args[2]['groupScopes']['same-group:set'])
        self.keys._fence.assert_not_called()

    def test_detached_or_superseded_groups_do_not_require_membership_lookup(self):
        self.authority_setup()
        self.document['groupScopes']['named-circle:old-set']=[self.object_row,self.edge]
        self.authority()
        self.keys._load_current.assert_called_once_with(self.db,'tenant',100,'same-group','set')
        self.keys._load_current.reset_mock()
        for snapshot in [None,{'objectSet':{'stated':0}}]:
            self.projection['snapshot']=snapshot
            self.authority()
        self.keys._load_current.assert_not_called()

    def test_authority_empty_and_oversized_scope_sets(self):
        self.authority_setup();self.document['groupScopes']={}
        self.media._group_object_projection.return_value=None
        self.assertIsNone(self.authority()['projection'])
        self.keys._load_current.assert_not_called()
        for invalid in [[],{str(i):[] for i in range(9)}]:
            self.document['groupScopes']=invalid
            with self.assertRaises(AdmissionRejected):self.authority()
