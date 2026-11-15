"""Mock-only joint item/group protected preparation units."""
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
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
