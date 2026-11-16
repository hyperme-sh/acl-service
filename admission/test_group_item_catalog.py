"""Mock-only catalog filtering and checkpoint boundary units."""
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from group_item_source import GroupItemSource
from group_item_grants import grant_key
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict

class GroupItemCatalogTests(TestCase):
    def setUp(self):
        self.scope=['same-group','set'];self.token=encoded(self.scope).decode('ascii')
        self.doc={'groupItemWraps':{self.token:{}},'groupItemStatuses':{grant_key(*self.scope,'reader'):{}}}
        self.documents={f'media{i}':dict(self.doc) for i in range(6)}
        self.db=Mock();self.db.execute.side_effect=self.query
        @contextmanager
        def transaction(*,write,before_commit):
            self.assertFalse(write);yield self.db;before_commit()
        self.store=SimpleNamespace(_transaction=transaction,active_media_index=False)
        self.media=Mock(tenant='tenant',clock=lambda:100)
        self.source=GroupItemSource(SimpleNamespace(media=self.media,store=self.store))
        self.source._read_permit=Mock(return_value=(object(),{'owner':'owner'},None,None))
    def query(self,sql,args=()):
        if sql.startswith('SELECT object'):return Mock(fetchall=lambda:[(key,) for key in sorted(self.documents)])
        doc=self.documents.get(args[0]);return Mock(fetchone=lambda:None if doc is None else (1,b'n',json.dumps(doc).encode()))
    def catalog(self,**changes):
        args=dict(tenant='tenant',reader='reader',page=0);args.update(changes);return self.source.reader_catalog(**args)
    def test_filter_before_paging_and_no_metadata_disclosure(self):
        self.documents['media0']={'deletion':{}};self.documents['media1']={}
        result=self.catalog();self.assertEqual([v['object'] for v in result['entries']],['media2','media3','media4','media5'])
        self.assertEqual(set(result['entries'][0]),{'object','predicate','set'})
        self.assertEqual(self.catalog(page=1)['entries'],[]);self.assertIsNone(self.catalog(page=15)['nextPage'])
        self.assertEqual(self.media._checkpoint.call_count,18)
    def test_only_current_joint_authority_is_visible(self):
        def permit(db,tenant,reader,object,*args):
            if object=='media0':raise AdmissionRejected('revoked')
            return object,{'owner':reader if object=='media1' else 'owner'},None,None
        self.source._read_permit.side_effect=permit
        self.assertEqual([v['object'] for v in self.catalog()['entries']],['media2','media3','media4','media5'])
        self.source._read_permit.side_effect=HistoryConflict('checkpoint changed')
        with self.assertRaises(HistoryConflict):self.catalog()
    def test_missing_or_corrupt_primary_and_checkpoint_fail_closed(self):
        self.documents={'missing':None}
        with self.assertRaises(AdmissionRejected):self.catalog()
        self.documents={'media':self.doc};self.media._checkpoint.side_effect=HistoryConflict('missing checkpoint')
        with self.assertRaises(HistoryConflict):self.catalog()
    def test_capacity_scope_and_input_bounds(self):
        for args in ({'tenant':'other'},{'reader':None},{'page':True},{'page':-1},{'page':16}):
            with self.assertRaises(AdmissionRejected):self.catalog(**args)
        self.documents={str(i):self.doc for i in range(65)}
        with self.assertRaises(AdmissionRejected):self.catalog()
        for wraps in ([],{str(i):{} for i in range(9)},{'null':{}},{'["bad","set"]':{}},{'["same-group",1]':{}},{'[ "same-group", "set"]':{}}):
            self.documents={'media':{**self.doc,'groupItemWraps':wraps}}
            with self.assertRaises(AdmissionRejected):self.catalog()
    def test_active_index_and_cancellation_are_preserved(self):
        self.store.active_media_index=True;self.catalog()
        self.assertIn('freshness.media_active',self.db.execute.call_args_list[0].args[0])
        self.media._guard.side_effect=TimeoutError()
        with self.assertRaises(TimeoutError):self.catalog()
