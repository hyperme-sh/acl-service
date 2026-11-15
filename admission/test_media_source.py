"""Protected journal/rollback contracts. SQLite and native work run in CI only."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from unittest import TestCase, IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

from media_source import MediaSource, encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
from acl_service.infrastructure.initialize_ciphertext_freshness import initialize

TENANT='01234567-89ab-cdef-0123-456789abcdef'
OBJECT='media_test'


class MediaSourceContracts(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.db'; self.anchor=Path(self.tmp.name)/'freshness.db'
        store=SqliteHistoryStore(self.path)
        for who in ('owner','reader'): store.enroll(who,b'{}')
        initialize(self.path,hashlib.sha256(self.path.read_bytes()).hexdigest(),self.anchor)
        self.store=SqliteHistoryStore(self.path,freshness_path=self.anchor,require_authority_checkpoint=True)
        self.now=100
        self.ids={'owner':'owner','bindings':{'owner':{'pub':'owner-key','epub':'owner-epub','head':0},
                                             'reader':{'pub':'reader-key','epub':'reader-epub','head':0}}}
        self.identities=Mock(side_effect=lambda *args:json.loads(json.dumps(self.ids)))
        self.native=tuple(Mock() for _ in range(5))
        self.native[0].matches_grant.return_value=True
        self.native[1].matches_status.return_value=True
        self.native[2].matches_manifest.return_value=True
        self.native[3].matches_settled.return_value=True
        self.native[4].verifies_history.return_value=True
        self.source=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        self.source.provision(OBJECT,{},10000,exclusive_grant=lambda *args:True)

    def test_group_commands_use_bounded_existing_worker_and_fixed_arguments(self):
        with patch('group_source.GroupSource') as groups, patch('group_membership.GroupMembership') as members, patch('group_key_source.GroupKeySource') as key_sources:
            group=groups.return_value;member=members.return_value;keys=key_sources.return_value
            scope={'predicate':'same-group','set':'set_test'}
            cases=[('key-view',scope,keys.view),
                   ('key-state',{**scope,'command':{}},keys.state),
                   ('key-append',{**scope,'at':100,'fence':'f','command':{}},keys.append),
                   ('catalog',{'page':0},member.catalog),
                   ('create-view',{**scope,'object':OBJECT},group.creation_view),
                   ('create-state',{**scope,'object':OBJECT,'config':{}},group.creation_state),
                   ('create',{**scope,'object':OBJECT,'at':100,'fence':'f','config':{}},group.create),
                   ('member-view',{**scope,'member':'reader','role':'member','stated':1},member.view),
                   ('member-state',{**scope,'member':'reader','role':'member','row':{}},member.state),
                   ('member-append',{**scope,'member':'reader','role':'member','row':{},'at':100,'fence':'f'},member.append)]
            for action,body,method in cases:
                method.return_value=True if action in ('create','member-append','key-append') else {'ok':True}
                result=asyncio.run(self.source.group_operation(action,TENANT,'owner',body))
                self.assertEqual(result,{'accepted':True} if action in ('create','member-append','key-append') else {'ok':True})
                self.assertEqual(method.call_args.args[:2],(TENANT,'owner'))
                self.assertTrue(callable(method.call_args.args[-1]))
            with self.assertRaises(AdmissionRejected):asyncio.run(self.source.group_operation('unknown',TENANT,'owner',scope))
            with self.assertRaises(AdmissionRejected):asyncio.run(self.source.group_operation('create',TENANT,'owner',{'padding':'x'*18433}))

    def test_group_item_epoch_bridge_preserves_authenticated_arguments(self):
        with patch('group_source.GroupSource'), patch('group_key_source.GroupKeySource'), patch('group_item_source.GroupItemSource') as items:
            items.return_value.epoch_view.return_value={'at':100,'snapshot':{}}
            self.assertEqual(asyncio.run(self.source.group_item_epoch_view(TENANT,'owner',OBJECT,'same-group','set_test')),{'at':100,'snapshot':{}})
            args=items.return_value.epoch_view.call_args.args
            self.assertEqual(args[:-1],(TENANT,'owner',OBJECT,'same-group','set_test'))
            self.assertTrue(callable(args[-1]))

    def test_group_item_read_bridge_keeps_scope_and_commit_permit(self):
        with patch('group_source.GroupSource'), patch('group_key_source.GroupKeySource'), patch('group_item_source.GroupItemSource') as items:
            permit=object();items.return_value.authorize_read.return_value=permit
            items.return_value.commit_read.return_value=True
            self.assertIs(asyncio.run(self.source.authorize_group_item_read(TENANT,'reader',OBJECT,'same-group','set_test')),permit)
            self.assertEqual(items.return_value.authorize_read.call_args.args,(TENANT,'reader',OBJECT,'same-group','set_test'))
            self.assertTrue(asyncio.run(self.source.commit_group_item_read(permit)))
            self.assertEqual(items.return_value.commit_read.call_args.args,(permit,))
            self.assertTrue(callable(items.return_value.commit_read.call_args.kwargs['cancel']))

    def test_group_item_status_bridge_keeps_owner_scope(self):
        with patch('group_source.GroupSource'), patch('group_key_source.GroupKeySource'), patch('group_item_source.GroupItemSource') as items:
            source=items.return_value;source.status_view.return_value={'at':100};source.append_status.return_value=True
            self.assertEqual(asyncio.run(self.source.group_item_status_view(TENANT,'owner',OBJECT,'same-group','set_test','reader')),{'at':100})
            self.assertEqual(source.status_view.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test','reader'))
            self.assertTrue(asyncio.run(self.source.append_group_item_status(TENANT,'owner',OBJECT,'same-group','set_test','reader',100,'f',{})))
            self.assertEqual(source.append_status.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test','reader',100,'f',{}))
            self.assertTrue(callable(source.append_status.call_args.kwargs['cancel']))
            source.status_state.return_value={'state':'applied'}
            self.assertEqual(asyncio.run(self.source.group_item_status_state(TENANT,'owner',OBJECT,'same-group','set_test','reader',{})),{'state':'applied'})
            self.assertEqual(source.status_state.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test','reader',{}))

    def test_group_item_grant_bridge_keeps_fixed_arguments_and_bounded_worker(self):
        with patch('group_source.GroupSource'), patch('group_key_source.GroupKeySource'), patch('group_item_source.GroupItemSource'), patch('group_item_grants.GroupItemGrants') as grants:
            source=grants.return_value;source.view.return_value={'at':100};source.append.return_value=True;source.state.return_value={'state':'applied'}
            self.assertEqual(asyncio.run(self.source.group_item_grant_view(TENANT,'owner',OBJECT,'same-group','set_test','reader',False)),{'at':100})
            self.assertTrue(asyncio.run(self.source.append_group_item_grant(TENANT,'owner',OBJECT,'same-group','set_test',100,'f',{})))
            self.assertEqual(source.view.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test','reader',False))
            self.assertEqual(source.append.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test',100,'f',{}))
            self.assertEqual(asyncio.run(self.source.group_item_grant_state(TENANT,'owner',OBJECT,'same-group','set_test',{})),{'state':'applied'})
            self.assertEqual(source.state.call_args.args,(TENANT,'owner',OBJECT,'same-group','set_test',{}))
            self.assertTrue(callable(source.append.call_args.kwargs['cancel']))

    def test_group_grant_capacity_is_preserved_across_ordinary_writes_and_rollback(self):
        from group_item_grants import reserve,version_reserve
        grant={'predicate':'same-group','set':'set_test',**self.grant(),'ownerPub':'owner-key'}
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['groupItemGrants']={'rows':[grant],'frozen':[],'conflicts':[]}
            self.source._save(db,OBJECT,row,doc)
        before=self.source.read_view(OBJECT,100)['fence']
        self.assertEqual(self.source.read_view(OBJECT,100)['snapshot']['entries'],[])
        for mutation in ['bytes','version']:
            with self.assertRaises(AdmissionRejected):
                with self.store._transaction(write=True) as db:
                    row,doc=self.source._load(db,OBJECT,100)
                    if mutation=='bytes':doc['padding']='x'*(6*1024*1024-len(encoded(doc))-10)
                    else:doc['objectVersion']=9007199254740991-version_reserve(doc)+1
                    self.source._save(db,OBJECT,row,doc)
            self.assertEqual(self.source.read_view(OBJECT,100)['fence'],before)
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['objectVersion']=9007199254740991-version_reserve(doc)
            self.source._save(db,OBJECT,row,doc)
            row,doc=self.source._load(db,OBJECT,100)
            doc['groupItemGrants']['rows'].append({**grant,'claims':{**grant['claims'],'stated':0,'grantRevision':2}})
            doc['objectVersion']+=1
            self.source._save(db,OBJECT,row,doc)
            self.assertEqual(version_reserve(doc),1)
            self.assertGreater(reserve(doc),0)

    def test_consent_view_is_bound_to_member_history_and_one_source_fence(self):
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['groupScopes']={'same-group:set_test':[{'signed':'invitation'}]}
            self.source._save(db,OBJECT,row,doc)
        consent={'memberPub':'reader-key','draft':{'member':'reader','role':'member'}}
        with patch('media_source.HistoryAdmission._run_verifier',return_value=encoded(consent)) as verify:
            held=asyncio.run(self.source.member_group_consent_view(TENANT,'reader',OBJECT,'same-group','set_test'))
            self.assertEqual(held['at'],100);self.assertEqual(held['consent'],consent)
            self.assertEqual(verify.call_args.kwargs['groupConsentGraph'],{'member':'reader','object':OBJECT,
                'predicate':'same-group','set':'set_test','rows':[{'signed':'invitation'}]})
            again=self.source.group_consent_view(TENANT,'reader',OBJECT,100,'same-group','set_test')
            self.assertEqual(held['fence'],again['fence'])
            verify.return_value=encoded({**consent,'memberPub':'obsolete'})
            with self.assertRaises(AdmissionRejected):self.source.group_consent_view(TENANT,'reader',OBJECT,100,'same-group','set_test')
        for tenant,member,predicate,set_id in [('other','reader','same-group','set_test'),
            (TENANT,'outsider','same-group','set_test'),(TENANT,'reader','same-group','set_missing'),
            (TENANT,'reader','other','set_test')]:
            with self.assertRaises(AdmissionRejected):self.source.group_consent_view(tenant,member,OBJECT,100,predicate,set_id)
        def cancel():raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):self.source.group_consent_view(TENANT,'reader',OBJECT,100,'same-group','set_test',cancel)

    @staticmethod
    def group_member_row():
        return {'kind':'membership','soul':'membership-soul','record':{'role':'member','predicate':'same-group',
            'set':'set_test','member':'reader','setOwner':'owner','hamState':1,'stated':1,
            'issuedAt':100,'cancels':[],'sig':'signed'}}

    def member_write_fixture(self):
        view=self.group_fixture()
        invitation=self.group_member_row();invitation['record']['role']='set'
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{'kind':'object'},invitation])
        row=self.group_member_row();row['record']['hamState']=2
        draft={key:value for key,value in row['record'].items() if key not in ('sig','stated')}
        context={'memberPub':'reader-key','state':{},'draft':draft}
        held=patch.object(self.source,'_group_member_context',return_value=context)
        resolve=held.start();self.addCleanup(held.stop)
        return row,context,resolve

    def test_member_write_and_exact_recovery_preserve_fixed_identity_and_fences(self):
        row,context,resolve=self.member_write_fixture()
        check=lambda value=row:asyncio.run(self.source.member_group_append_state(TENANT,'reader',OBJECT,'same-group','set_test',value))
        append=lambda value,fence:asyncio.run(self.source.member_append_group(TENANT,'reader',OBJECT,100,fence,'same-group','set_test',value))
        first=check();self.assertEqual(first['state'],'absent')
        self.assertTrue(append(row,first['fence']))
        applied=check();self.assertEqual(applied['state'],'applied');self.assertNotEqual(applied['fence'],first['fence'])
        self.assertTrue(append(row,applied['fence']));self.assertEqual(check()['fence'],applied['fence'])
        with self.assertRaises(HistoryConflict):append(row,first['fence'])
        withdrawal={**row,'record':{**row['record'],'stated':0}}
        prepared=asyncio.run(self.source.member_group_withdrawal_view(TENANT,'reader',OBJECT,'same-group','set_test'))
        self.assertEqual(prepared['at'],100);self.assertEqual(resolve.call_args.args[-1],True)
        self.assertTrue(append(withdrawal,prepared['fence']))
        self.assertEqual(resolve.call_args.args[-1],True)
        self.assertEqual(check(withdrawal)['state'],'applied')
        self.assertEqual(self.source.read_view(OBJECT,100)['snapshot']['entries'],[])

    def test_member_history_quota_preserves_retry_withdrawal_and_other_members(self):
        row,context,_=self.member_write_fixture()
        def append(value,member='reader'):
            check=self.source.member_group_state(TENANT,member,OBJECT,100,'same-group','set_test',value)
            return self.source.append_member_group(TENANT,member,OBJECT,100,check['fence'],'same-group','set_test',value)
        for ham in range(2,10):
            row={**row,'record':{**row['record'],'hamState':ham}}
            context['draft']['hamState']=ham
            self.assertTrue(append(row))
        self.assertTrue(append(row))  # exact retry consumes nothing
        ninth={**row,'record':{**row['record'],'hamState':10}}
        context['draft']['hamState']=10
        before=self.source.member_group_state(TENANT,'reader',OBJECT,100,'same-group','set_test',ninth)['fence']
        with self.assertRaisesRegex(AdmissionRejected,'member consent history exhausted'):append(ninth)
        self.assertEqual(self.source.member_group_state(TENANT,'reader',OBJECT,100,'same-group','set_test',ninth)['fence'],before)
        context['draft']['hamState']=9
        self.assertTrue(append({**row,'record':{**row['record'],'stated':0}}))
        other={**row,'record':{**row['record'],'member':'owner','hamState':2}}
        context['memberPub']='owner-key';context['draft']['member']='owner';context['draft']['hamState']=2
        self.assertTrue(append(other,'owner'))

    def test_member_write_refuses_changed_context_before_committing(self):
        row,context,resolve=self.member_write_fixture()
        view=lambda:self.source.member_group_state(TENANT,'reader',OBJECT,100,'same-group','set_test',row)
        append=lambda value=row:self.source.append_member_group(TENANT,'reader',OBJECT,100,view()['fence'],'same-group','set_test',value)
        before=view()['fence']
        context['memberPub']='obsolete'
        with self.assertRaises(AdmissionRejected):append()
        context['memberPub']='reader-key';context['draft']['hamState']=3
        with self.assertRaises(AdmissionRejected):append()
        context['draft']['hamState']=2
        resolve.side_effect=AdmissionRejected('invitation withdrawn')
        with self.assertRaises(AdmissionRejected):append()
        resolve.side_effect=None
        self.assertEqual(view()['fence'],before)
        with self.store._transaction(write=True) as db:
            held,doc=self.source._load(db,OBJECT,100)
            # Exercise the existing terminal-version guard without changing a
            # reservation-enabled journal's valid production state.
            doc.pop('groupWithdrawalCapacity');doc['objectVersion']=9007199254740991
            self.source._save(db,OBJECT,held,doc)
        with self.assertRaises(AdmissionRejected):append()

    def test_member_signed_draft_can_cross_a_second_but_expires_without_application(self):
        row,_,_=self.member_write_fixture()
        self.now=101
        held=self.source.member_group_state(TENANT,'reader',OBJECT,101,'same-group','set_test',row)
        self.assertTrue(self.source.append_member_group(TENANT,'reader',OBJECT,101,held['fence'],'same-group','set_test',row))
        self.now=106
        withdrawal={**row,'record':{**row['record'],'stated':0}}
        held=self.source.member_group_state(TENANT,'reader',OBJECT,106,'same-group','set_test',withdrawal)
        with self.assertRaises(AdmissionRejected):self.source.append_member_group(TENANT,'reader',OBJECT,106,held['fence'],'same-group','set_test',withdrawal)
        self.assertEqual(self.source.member_group_state(TENANT,'reader',OBJECT,106,'same-group','set_test',withdrawal)['state'],'absent')
        # Exact historical application is still queryable after its signing window.
        self.assertEqual(self.source.member_group_state(TENANT,'reader',OBJECT,106,'same-group','set_test',row)['state'],'applied')

    def test_member_write_boundaries_and_commit_cancellation(self):
        row,_,_=self.member_write_fixture()
        for bad in [None,{}, {**row,'kind':'object-set'},{**row,'extra':1},
            {**row,'record':{**row['record'],'role':'set'}},{**row,'record':{**row['record'],'member':'owner'}},
            {**row,'record':{**row['record'],'stated':True}},{**row,'record':{**row['record'],'sig':'x'*129}},
            {**row,'record':{**row['record'],'sig':''}},{**row,'record':{**row['record'],'extra':1}},
            {**row,'soul':'x'*8192}]:
            with self.assertRaises(AdmissionRejected):self.source._member_group_row(bad,'reader','same-group','set_test')
        fence=self.source.member_group_state(TENANT,'reader',OBJECT,100,'same-group','set_test',row)['fence']
        for tenant,member,set_id,value in [('other','reader','set_test',row),
            (TENANT,'outsider','set_test',{**row,'record':{**row['record'],'member':'outsider'}}),
            (TENANT,'reader','set_missing',{**row,'record':{**row['record'],'set':'set_missing'}})]:
            with self.assertRaises(AdmissionRejected):self.source.member_group_state(tenant,member,OBJECT,100,'same-group',set_id,value)
            with self.assertRaises(AdmissionRejected):self.source.append_member_group(tenant,member,OBJECT,100,fence,'same-group',set_id,value)
        calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls>1:raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):self.source.append_member_group(TENANT,'reader',OBJECT,100,fence,'same-group','set_test',row,cancel)
        self.assertEqual(self.source.member_group_state(TENANT,'reader',OBJECT,100,'same-group','set_test',row)['state'],'absent')

    def group_fixture(self):
        def verify(principal,at,**inputs):
            graph=inputs['groupGraph']
            self.assertEqual(graph['object'],OBJECT)
            if any(row.get('bad') for row in graph['rows']): raise AdmissionRejected('signature refused')
            return encoded({**{k:v for k,v in graph.items() if k!='rows'},'members':[]})
        held=patch('media_source.HistoryAdmission._run_verifier',side_effect=verify)
        held.start();self.addCleanup(held.stop)
        return lambda:self.source.group_view(TENANT,'owner',OBJECT,self.now,'same-group','set_test')

    def policy_fixture(self):
        context={'owner':'reader','ownerPub':'reader-key','setId':'set_test','predicate':'same-group'}
        held=patch.object(self.source,'_group_policy_context',return_value=context)
        held.start();self.addCleanup(held.stop)
        verifier=Mock()
        verifier.matches_config.side_effect=lambda proof,expected: all(json.loads(proof)[k]==v for k,v in json.loads(expected).items() if k!='ownerPub') and json.loads(proof)['signature']==json.loads(expected)['ownerPub']
        held=patch('media_source.GroupEpochConfigVerifier',return_value=verifier)
        held.start();self.addCleanup(held.stop)
        config={'owner':'reader','setId':'set_test','predicate':'same-group','settleWindowMs':3600000,'configRevision':1,'signature':'reader-key'}
        def view():return self.source.group_policy_view(TENANT,'owner',OBJECT,100,'same-group','set_test')
        def append(value,fence=None,**kwargs):return self.source.append_group_policy(TENANT,'owner',OBJECT,100,fence or view()['fence'],'same-group','set_test',value,**kwargs)
        return context,config,view,append

    def test_group_authority_view_reads_direct_group_policy_and_keys_in_one_transaction(self):
        context,config,policy_view,append=self.policy_fixture()
        append(config)
        self.mutate('grant',self.grant())
        projection={'object':OBJECT,'predicate':'same-group','set':'set_test','members':['reader'],
                    'snapshot':{'objectSet':{'predicate':'same-group','setId':'set_test','stated':1,'hamState':7},
                                'members':[{'accessor':'reader','predicate':'same-group','setId':'set_test','stated':1,'hamState':5}]}}
        connections=[]
        self.identities.side_effect=lambda db,*args:(connections.append(db) or json.loads(json.dumps(self.ids)))
        def project(db,*args):
            connections.append(db)
            return json.loads(json.dumps(projection))
        def current(db,*args):
            connections.append(db)
            return context
        with patch.object(self.source,'_group_object_projection',side_effect=project), patch.object(self.source,'_group_policy_context',side_effect=current):
            held=asyncio.run(self.source.owner_group_authority_view(TENANT,'owner',OBJECT))
            self.assertEqual(held['at'],100)
            self.assertEqual(held['projection'],projection)
            self.assertEqual(held['policy'],{'context':context,'config':config})
            self.assertEqual(set(held['bindings']),{'owner','reader'})
            self.assertEqual(held['direct']['entries'][0]['scope'],'direct')
            self.assertTrue(all(db is connections[0] for db in connections))
            before=held['fence']
            self.store.append('reader',0,b'{}')
            after=self.source.group_authority_view(TENANT,'owner',OBJECT,100)
            self.assertNotEqual(before,after['fence'])
            context['ownerPub']='rotated'
            self.assertIsNone(self.source.group_authority_view(TENANT,'owner',OBJECT,100)['policy']['config'])
            del self.ids['bindings']['reader']
            with self.assertRaises(AdmissionRejected):self.source.group_authority_view(TENANT,'owner',OBJECT,100)

    def test_group_authority_view_empty_cancelled_and_unauthorized(self):
        held=self.source.group_authority_view(TENANT,'owner',OBJECT,100)
        self.assertIsNone(held['projection']);self.assertIsNone(held['policy'])
        self.assertEqual(held['direct'],{'entries':[]});self.assertEqual(set(held['bindings']),{'owner'})
        with patch.object(self.source,'_group_object_projection',return_value={'snapshot':None}), patch.object(self.source,'_group_policy_context') as policy:
            self.assertIsNone(self.source.group_authority_view(TENANT,'owner',OBJECT,100)['policy'])
            policy.assert_not_called()
        for tenant,writer in [('bad','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.group_authority_view(tenant,writer,OBJECT,100)
        calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls>1:raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):self.source.group_authority_view(TENANT,'owner',OBJECT,100,cancel)

    def test_group_append_advances_object_version_only_for_changed_rows(self):
        view=self.group_fixture()
        before=self.source.read_view(OBJECT,100)['objectVersion']
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{}])
        self.assertEqual(self.source.read_view(OBJECT,100)['objectVersion'],before+1)
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{}])
        self.assertEqual(self.source.read_view(OBJECT,100)['objectVersion'],before+1)
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['objectVersion']=9007199254740991
            self.source._save(db,OBJECT,row,doc)
        with self.assertRaises(AdmissionRejected):
            self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{'new':1}])
        self.assertEqual(view()['rows'],[{}])

    def test_group_policy_current_owner_selection_and_detached_storage(self):
        context,config,view,append=self.policy_fixture()
        self.assertIsNone(view()['config'])
        first=view()['fence'];append(config)
        self.assertEqual(view()['config'],config)
        with self.assertRaises(HistoryConflict):append(config,first)
        held=view()['fence'];append(config);self.assertEqual(view()['fence'],held)
        config['settleWindowMs']=7200000;append(config)
        candidates=[{**config,'settleWindowMs':3600000},config]
        self.assertEqual(view()['config'],min(candidates,key=self.source._group_policy_digest))
        high={**config,'configRevision':2};append(high)
        config['signature']='changed'
        self.assertEqual(view()['config'],high)
        context['ownerPub']='rotated'
        self.assertIsNone(view()['config'])
        with self.assertRaises(AdmissionRejected):append(high)
        current={**high,'signature':'rotated'};append(current)
        self.assertEqual(view()['config'],current)
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,100)
            self.assertEqual(doc['objectVersion'],4)
            self.assertEqual(doc['grants'],[])

    def test_group_policy_bounds_authorization_and_atomic_cancellation(self):
        context,config,view,append=self.policy_fixture()
        for bad in [None,{}, {**config,'extra':1},{**config,'signature':''},{**config,'owner':2},
                    {**config,'configRevision':True},{**config,'configRevision':-1},
                    {**config,'configRevision':9007199254740992},{**config,'settleWindowMs':1},
                    {**config,'settleWindowMs':True},{**config,'signature':'x'*1025},
                    {**config,'owner':'owner'},{**config,'setId':'set_other'},{**config,'predicate':'named-circle'}]:
            with self.assertRaises(AdmissionRejected):append(bad)
        for tenant,writer in [('bad','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.group_policy_view(tenant,writer,OBJECT,100,'same-group','set_test')
            with self.assertRaises(AdmissionRejected):self.source.append_group_policy(tenant,writer,OBJECT,100,view()['fence'],'same-group','set_test',config)
        with self.assertRaises(HistoryConflict):append(config,'bad')
        calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls>1:raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):append(config,cancel=cancel)
        self.assertIsNone(view()['config'])
        for revision in range(64):append({**config,'configRevision':revision})
        with self.assertRaises(AdmissionRejected):append({**config,'configRevision':64})
        append(config)  # Exact replay remains possible at capacity.

    def test_group_policy_async_bridge_preserves_current_context_and_copies_input(self):
        context,config,view,append=self.policy_fixture()
        draft=asyncio.run(self.source.owner_group_policy_view(TENANT,'owner',OBJECT,'same-group','set_test'))
        self.assertEqual(draft['at'],100)
        self.assertEqual(draft['context'],context)
        self.assertTrue(asyncio.run(self.source.owner_append_group_policy(TENANT,'owner',OBJECT,100,draft['fence'],'same-group','set_test',config)))
        self.assertEqual(view()['config'],config)
        with self.assertRaises(AdmissionRejected):
            asyncio.run(self.source.owner_append_group_policy(TENANT,'owner',OBJECT,100,draft['fence'],'same-group','set_test',{}))

    def test_group_policy_context_uses_only_admitted_rows(self):
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,100)
            with self.assertRaises(AdmissionRejected):self.source._group_policy_context(db,OBJECT,doc,100,'same-group','set_test')
            doc['groupScopes']={'same-group:set_test':[{'signed':'row'}]}
            with patch('media_source.HistoryAdmission._run_verifier',return_value=b'{"owner":"reader"}') as verify:
                self.assertEqual(self.source._group_policy_context(db,OBJECT,doc,100,'same-group','set_test'),{'owner':'reader'})
                self.assertEqual(verify.call_args.kwargs['groupPolicyGraph'],{'object':OBJECT,'predicate':'same-group','set':'set_test','rows':[{'signed':'row'}]})

    def test_group_append_reconciliation_is_exact_current_and_read_only(self):
        view=self.group_fixture()
        rows=[{'kind':'object'},self.group_member_row()]
        check=lambda values=rows:self.source.group_append_state(TENANT,'owner',OBJECT,100,'same-group','set_test',values)
        first=view();self.assertEqual(check()['state'],'absent');self.assertEqual(view()['fence'],first['fence'])
        self.source.append_group(TENANT,'owner',OBJECT,100,first['fence'],'same-group','set_test',rows[:1])
        self.assertEqual(check()['state'],'absent')
        held=check();self.source.append_group(TENANT,'owner',OBJECT,100,held['fence'],'same-group','set_test',rows)
        applied=check();self.assertEqual(applied['state'],'applied')
        self.assertEqual(check(rows+rows)['state'],'applied')
        self.assertEqual(check([{**self.group_member_row(),'changed':True}])['state'],'absent')
        self.assertEqual(view()['fence'],applied['fence'])
        current=asyncio.run(self.source.owner_group_append_state(TENANT,'owner',OBJECT,'same-group','set_test',rows))
        self.assertEqual(current,{'at':100,**applied})
        self.store.append('reader',0,b'{}')
        self.assertNotEqual(check()['fence'],applied['fence'])
        with patch('media_source.HistoryAdmission._run_verifier',side_effect=AdmissionRejected('history changed')):
            with self.assertRaises(AdmissionRejected):check()

    def test_group_reconciliation_and_deduplication_preserve_json_types(self):
        view=self.group_fixture()
        numeric={'kind':'row','record':{'stated':1,'nested':[0]}}
        reordered={'record':{'nested':[0],'stated':1},'kind':'row'}
        boolean={'kind':'row','record':{'stated':True,'nested':[False]}}
        self.assertEqual(len(self.source._group_candidate([numeric],[reordered])),1)
        self.assertEqual(len(self.source._group_candidate([numeric],[boolean,boolean])),2)
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[numeric])
        check=lambda row:self.source.group_append_state(TENANT,'owner',OBJECT,100,'same-group','set_test',[row])
        self.assertEqual(check(reordered)['state'],'applied')
        self.assertEqual(check(boolean)['state'],'absent')
        # The mock verifier accepts arbitrary rows; the native contract below
        # separately requires the differently typed signed row to be refused.
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[boolean])
        self.assertEqual(len(view()['rows']),2)

    def test_group_append_reconciliation_refuses_boundaries_and_cancellation(self):
        self.group_fixture()
        for tenant,writer in [('bad','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.group_append_state(tenant,writer,OBJECT,100,'same-group','set_test',[{}])
        for rows in [None,[],[{}]*65,[{'large':'x'*65536}],[{'bad':True}]]:
            with self.assertRaises(AdmissionRejected):self.source.group_append_state(TENANT,'owner',OBJECT,100,'same-group','set_test',rows)
        calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls>1:raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):self.source.group_append_state(TENANT,'owner',OBJECT,100,'same-group','set_test',[{}],cancel)
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['groupScopes']={f'same-group:set_{n}':[{}] for n in range(8)}
            self.source._save(db,OBJECT,row,doc)
        with self.assertRaises(AdmissionRejected):self.source.group_append_state(TENANT,'owner',OBJECT,100,'same-group','set_new',[{}])

    def test_group_journal_retains_cancellation_and_rejects_stale_writes(self):
        view=self.group_fixture()
        first=view();self.assertIsNone(first['projection'])
        rows=[{'kind':'object'},self.group_member_row(),{'kind':'cancel'}]
        self.source.append_group(TENANT,'owner',OBJECT,100,first['fence'],'same-group','set_test',rows)
        current=view();self.assertEqual(current['rows'],rows)
        self.assertEqual(current['projection']['members'],[])
        with self.assertRaises(HistoryConflict):
            self.source.append_group(TENANT,'owner',OBJECT,100,first['fence'],'same-group','set_test',rows)
        self.source.append_group(TENANT,'owner',OBJECT,100,current['fence'],'same-group','set_test',rows)
        self.assertEqual(view()['fence'],current['fence'])
        self.assertEqual(self.source.read_view(OBJECT,100)['snapshot'],{'entries':[]})
        self.store.append('reader',0,b'{}')
        with self.assertRaises(HistoryConflict):
            self.source.append_group(TENANT,'owner',OBJECT,100,current['fence'],'same-group','set_test',[{}])

    def test_group_owner_async_bridge_uses_current_view_and_protected_append(self):
        self.group_fixture()
        view=asyncio.run(self.source.owner_group_view(TENANT,'owner',OBJECT))
        self.assertEqual(view['at'],100);self.assertIsNone(view['projection'])
        self.assertTrue(asyncio.run(self.source.owner_append_group(TENANT,'owner',OBJECT,100,view['fence'],'same-group','set_test',[{}])))
        for rows in ({},[{'large':'x'*65536}]):
            with self.assertRaises(AdmissionRejected):asyncio.run(self.source.owner_append_group(TENANT,'owner',OBJECT,100,view['fence'],'same-group','set_test',rows))

    def test_full_group_view_uses_all_retained_scopes_and_owner_boundary(self):
        view=self.group_fixture()
        self.assertIsNone(self.source.group_object_view(TENANT,'owner',OBJECT,100)['projection'])
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{}])
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'named-circle','set_other',[{}])
        with patch('media_source.HistoryAdmission._run_verifier',return_value=b'{"members":[]}') as verify:
            result=self.source.group_object_view(TENANT,'owner',OBJECT,100)
            self.assertEqual(result['projection'],{'members':[]})
            graph=verify.call_args.kwargs['groupObjectGraph']
            self.assertEqual(graph['object'],OBJECT)
            self.assertEqual({row['set'] for row in graph['scopes']},{'set_test','set_other'})
        for tenant,writer in [('wrong','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.group_object_view(tenant,writer,OBJECT,100)
        with patch('media_source.HistoryAdmission._run_verifier',side_effect=AdmissionRejected('history changed')):
            with self.assertRaises(AdmissionRejected):self.source.group_object_view(TENANT,'owner',OBJECT,100)

    def test_group_journal_deduplicates_inside_batch(self):
        view=self.group_fixture()
        rows=[{'kind':'object'}]*3
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',rows)
        self.assertEqual(view()['rows'],rows[:1])

    def test_group_journal_reserves_direct_cancellation_and_deletion_capacity(self):
        view=self.group_fixture()
        self.mutate('grant',self.grant())
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{}])
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['padding']='x'*(6*1024*1024-512*1024-64*17*1024-4096-len(encoded(doc))-100)
            self.source._save(db,OBJECT,row,doc)
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        self.assertEqual(self.source.read_view(OBJECT,100)['snapshot']['entries'][0]['stated'],0)
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['padding']+='x'*18000
            with self.assertRaises(AdmissionRejected):self.source._save(db,OBJECT,row,doc)
            doc['padding']=doc['padding'][:-18000]
            doc['deletion']={'command':'deleted'}
            self.source._save(db,OBJECT,row,doc)

    def test_legacy_group_capacity_does_not_block_direct_withdrawal(self):
        view=self.group_fixture()
        self.mutate('grant',self.grant())
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{}])
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc.pop('groupWithdrawalCapacity')
            doc['padding']='x'*(6*1024*1024-64*17*1024-4096-len(encoded(doc))-100)
            self.source._save(db,OBJECT,row,doc)
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        self.assertEqual(self.source.read_view(OBJECT,100)['snapshot']['entries'][0]['stated'],0)
        # A new group write cannot silently adopt a reservation that does not fit.
        before=view()['fence']
        with self.assertRaises(AdmissionRejected):
            self.source.append_group(TENANT,'owner',OBJECT,100,before,'same-group','set_test',[{'new':'row'}])
        self.assertEqual(view()['fence'],before)

    def test_group_capacity_reserves_both_parties_and_withdrawals_release_their_slots(self):
        def assent(role,stated=1,ham=1):
            return {'kind':'membership','soul':'membership-soul','record':{'role':role,'predicate':'same-group',
                'set':'set_test','member':'reader','setOwner':'owner','hamState':ham,'stated':stated,
                'issuedAt':100,'cancels':[],'sig':'signed'}}
        # One-sided invitations also retain a set-owner withdrawal slot.
        rows=[assent('set')]+[{}]*1022
        self.source._group_withdrawal_capacity({'scope':rows})
        with self.assertRaises(AdmissionRejected):self.source._group_withdrawal_capacity({'scope':rows+[{}]})
        self.source._group_withdrawal_capacity({'scope':rows+[assent('set',0)]})
        # Both parties need independent slots; neither can consume the other's.
        rows=[assent('set'),assent('member')]+[{}]*1020
        self.source._group_withdrawal_capacity({'scope':rows})
        with self.assertRaises(AdmissionRejected):self.source._group_withdrawal_capacity({'scope':rows+[{}]})
        self.source._group_withdrawal_capacity({'scope':rows+[assent('member',0),assent('set',0)]})
        # Older withdrawals do not erase a newer active assent's reservation.
        rows=[assent('member',0),assent('member',1,2)]+[{}]*1022
        with self.assertRaises(AdmissionRejected):self.source._group_withdrawal_capacity({'scope':rows})
        # Equal-HAM withdrawal wins in either input order, including MAX_SAFE_INTEGER.
        for pair in ([assent('set',1,9007199254740991),assent('set',0,9007199254740991)],
                     [assent('set',0,9007199254740991),assent('set',1,9007199254740991)]):
            self.source._group_withdrawal_capacity({'scope':pair+[{}]*1022})

    def test_group_withdrawal_reserves_version_width_at_exact_document_limit(self):
        view=self.group_fixture();join=self.group_member_row()
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[join])
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['objectVersion']=999;doc['padding']=''
            reserve=512*1024-len(encoded(doc['groupScopes']))+64*17*1024+4096+13
            doc['padding']='x'*(6*1024*1024-len(encoded(doc))-reserve)
            self.source._save(db,OBJECT,row,doc)
        withdrawal={**join,'record':{**join['record'],'stated':0}}
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[withdrawal])
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,100)
            self.assertEqual(doc['objectVersion'],1000)
            reserve=512*1024-len(encoded(doc['groupScopes']))+64*17*1024+4096+12
            self.assertEqual(len(encoded(doc))+reserve,6*1024*1024)

    def test_group_withdrawal_keeps_last_version_increment_available(self):
        view=self.group_fixture();join=self.group_member_row()
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[join])
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            doc['objectVersion']=9007199254740990
            self.source._save(db,OBJECT,row,doc)
        before=view()['fence']
        with self.assertRaises(AdmissionRejected):
            self.source.append_group(TENANT,'owner',OBJECT,100,before,'same-group','set_test',[{'extra':'row'}])
        self.assertEqual(view()['fence'],before)
        withdrawal={**join,'record':{**join['record'],'stated':0}}
        self.source.append_group(TENANT,'owner',OBJECT,100,before,'same-group','set_test',[withdrawal])
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,100)
            self.assertEqual(doc['objectVersion'],9007199254740991)

    def test_group_capacity_also_reserves_object_set_withdrawal(self):
        record={'owner':'owner','object':OBJECT,'predicate':'same-group','set':'set_test',
            'hamState':1,'stated':1,'issuedAt':100,'cancels':[],'sig':'signed'}
        edge={'kind':'object-set','soul':'edge-soul','record':record}
        rows=[edge]+[{}]*1022
        self.source._group_withdrawal_capacity({'scope':rows})
        with self.assertRaises(AdmissionRejected):self.source._group_withdrawal_capacity({'scope':rows+[{}]})
        self.source._group_withdrawal_capacity({'scope':rows+[{**edge,'record':{**record,'stated':0}}]})

    def test_group_capacity_reserves_bytes_across_scopes_before_atomic_save(self):
        view=self.group_fixture()
        record={'role':'member','predicate':'same-group','set':'set_test','member':'reader','setOwner':'owner',
                'hamState':1,'stated':1,'issuedAt':100,'cancels':[],'sig':'signed'}
        envelope={'kind':'membership','soul':'membership-soul','record':record}
        self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[envelope])
        before=view()['fence']
        with self.store._transaction(write=True) as db:
            row,doc=self.source._load(db,OBJECT,100)
            scopes=doc['groupScopes'];scopes['other']=[{'padding':''}]
            scopes['other'][0]['padding']='x'*(512*1024-len(encoded(scopes))-10)
            with self.assertRaises(AdmissionRejected):self.source._save(db,OBJECT,row,doc)
        self.assertEqual(view()['fence'],before)

    def test_group_journal_aggregate_byte_limit_rolls_back(self):
        view=self.group_fixture()
        for i in range(8):
            self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{'n':i,'value':'x'*65000}])
        with self.assertRaises(AdmissionRejected):
            self.source.append_group(TENANT,'owner',OBJECT,100,view()['fence'],'same-group','set_test',[{'n':9,'value':'x'*65000}])
        self.assertEqual(len(view()['rows']),8)

    def test_group_journal_rejects_invalid_access_input_and_signature(self):
        view=self.group_fixture();fence=view()['fence']
        for tenant,writer in [('foreign','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.group_view(tenant,writer,OBJECT,100,'same-group','set_test')
            with self.assertRaises(AdmissionRejected):self.source.append_group(tenant,writer,OBJECT,100,fence,'same-group','set_test',[{}])
        for predicate,set_id in [('other','set_test'),('same-group','wrong'),('same-group',None)]:
            with self.assertRaises(AdmissionRejected):self.source.group_view(TENANT,'owner',OBJECT,100,predicate,set_id)
        for rows in [[],[{}]*65,{'row':1},[{'value':'x'*65536}],[{'bad':True}]]:
            with self.assertRaises(AdmissionRejected):self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_test',rows)
        self.assertEqual(view()['rows'],[])
        self.assertEqual(view()['fence'],fence)

    def test_group_journal_commit_cancellation_and_checkpoint_rollback(self):
        view=self.group_fixture();fence=view()['fence'];calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls==2:raise HistoryConflict('cancelled')
        with self.assertRaises(HistoryConflict):
            self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_test',[{}],cancel)
        self.assertEqual(view()['rows'],[])
        backup=self.path.read_bytes()
        self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_test',[{}])
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):view()

    def test_group_journal_bounds_scopes_and_rows(self):
        self.group_fixture()
        for i in range(8):
            fence=self.source.read_view(OBJECT,100)['fence']
            self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_'+str(i),[{}])
        fence=self.source.read_view(OBJECT,100)['fence']
        with self.assertRaises(AdmissionRejected):self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_ninth',[{}])
        for i in range(16):
            fence=self.source.read_view(OBJECT,100)['fence']
            rows=[{'n':i*64+j} for j in range(64)]
            if i<15:self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_0',rows)
            else:
                with self.assertRaises(AdmissionRejected):self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_0',rows)
                self.source.append_group(TENANT,'owner',OBJECT,100,fence,'same-group','set_0',rows[:-1]+rows[:1])
        self.assertEqual(len(self.source.group_view(TENANT,'owner',OBJECT,100,'same-group','set_0')['rows']),1024)

    def enable_active_index(self):
        with self.store._transaction(write=False) as db:
            db.execute('CREATE TABLE freshness.media_active (object TEXT PRIMARY KEY)')
            db.execute('INSERT INTO freshness.media_active SELECT object FROM freshness.media_checkpoints')
        self.store.active_media_index=True

    def mutate(self,operation,payload,**kwargs):
        fence=self.source.read_view(OBJECT,self.now)['fence']
        return self.source.mutate(TENANT,'owner',OBJECT,self.now,fence,operation,payload,**kwargs)

    def grant(self,**changes):
        claims={'object':OBJECT,'owner':'owner','accessor':'reader','from':0,'until':9999000,
                'stated':1,'epoch':1,'grantRevision':1,'itemCiphertextDigest':'a'*64,**changes}
        return {'claims':claims,'proof':{'grantBytes':'signed','signature':'owner-signature'}}

    def ready(self):
        self.mutate('grant',self.grant())
        snapshot=self.source.read_view(OBJECT,self.now)['snapshot']
        self.mutate('epoch',{'document':{'manifest':{'epoch':1,'revisionId':'b'*64,'aclSnapshot':'c'*64},'snapshot':snapshot},
            'finalization':{'epoch':1,'revisionId':'b'*64,'previousEpoch':0,'previousFinalizationId':'','finalizationId':'d'*64}})
        self.mutate('wrap',{'reader':'reader','record':'e'*64,'digest':'f'*64,'epoch':1,'revisionId':'b'*64,
                            'readerEpub':'reader-epub','itemDigest':'a'*64})
        self.mutate('status',{'accessor':'reader','signedAt':100000,'maxAgeMs':60000})

    def permit(self): return self.source.authorize(TENANT,'reader',OBJECT)

    def catalog_fixture(self):
        owner='axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'
        prefix='media_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_'
        self.ids['owner']=owner
        self.ids['bindings'][owner]={'pub':owner,'epub':owner,'head':0}
        objects=[prefix+format(i,'032x') for i in range(6)]
        for object in objects:
            self.source.provision(object,{},10000,exclusive_grant=lambda *args:True)
        return owner,objects

    def test_reader_catalog_requires_current_grant_status_epoch_and_wrap(self):
        def catalog():return self.source._reader_catalog(TENANT,'reader',0,lambda:None)
        self.assertEqual(catalog(),{'at':100,'objects':[],'nextPage':1})
        self.ready()
        self.assertEqual(catalog()['objects'],[OBJECT])
        self.assertEqual(self.source._reader_catalog(TENANT,'owner',0,lambda:None)['objects'],[])
        for verifier,name in [(self.native[0],'matches_grant'),(self.native[1],'matches_status'),(self.native[3],'matches_settled')]:
            getattr(verifier,name).return_value=False
            self.assertEqual(catalog()['objects'],[])
            getattr(verifier,name).return_value=True
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        self.assertEqual(catalog()['objects'],[])

    def test_reader_visible_positions_do_not_depend_on_hidden_objects(self):
        self.ready()
        before=self.source._reader_catalog(TENANT,'reader',0,lambda:None)
        for i in range(8):self.source.provision('media_hidden_'+str(i),{},10000,exclusive_grant=lambda *args:True)
        self.assertEqual(self.source._reader_catalog(TENANT,'reader',0,lambda:None),before)
        self.assertEqual(self.source._reader_catalog(TENANT,'reader',1,lambda:None)['objects'],[])

    def test_reader_catalog_bounds_hidden_pages_and_cancellation(self):
        self.ready()
        self.assertEqual(self.source._reader_catalog(TENANT,'unknown',0,lambda:None),{'at':100,'objects':[],'nextPage':1})
        self.assertEqual(self.source._reader_catalog(TENANT,'reader',15,lambda:None),{'at':100,'objects':[],'nextPage':None})
        for page in (True,-1,16,'0'):
            with self.assertRaises(AdmissionRejected):self.source._reader_catalog(TENANT,'reader',page,lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._reader_catalog('other','reader',0,lambda:None)
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):self.source._reader_catalog(TENANT,'reader',0,cancel)
        self.now=10001
        self.assertEqual(self.source._reader_catalog(TENANT,'reader',0,lambda:None)['objects'],[])

    def test_reader_catalog_refuses_missing_primary_and_changed_checkpoint(self):
        self.ready()
        with self.store._transaction(write=False) as db:db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(OBJECT,))
        with self.assertRaises(AdmissionRejected):self.source._reader_catalog(TENANT,'reader',0,lambda:None)
        with self.store._transaction(write=False) as db:db.execute('DELETE FROM media_sources WHERE object=?',(OBJECT,))
        with self.assertRaises(AdmissionRejected):self.source._reader_catalog(TENANT,'reader',0,lambda:None)

    def test_reader_catalog_uses_active_index_and_never_fetches_storage(self):
        self.ready();self.enable_active_index()
        self.assertEqual(self.source._reader_catalog(TENANT,'reader',0,lambda:None)['objects'],[OBJECT])
        with self.store._transaction(write=False) as db:db.execute('DELETE FROM media_sources WHERE object=?',(OBJECT,))
        with self.assertRaises(AdmissionRejected):self.source._reader_catalog(TENANT,'reader',0,lambda:None)

    def test_owner_catalog_has_fixed_pages_without_unrelated_ids_or_positions(self):
        owner,objects=self.catalog_fixture()
        foreign='media_p_'+'0'*128+'_'+'0'*32
        self.source.provision(foreign,{},10000,exclusive_grant=lambda *args:True)
        first=self.source._owner_catalog(TENANT,owner,0,lambda:None)
        self.assertEqual(first,{'at':100,'objects':objects[:4],'nextPage':1})
        self.assertEqual(self.source._owner_catalog(TENANT,owner,1,lambda:None)['objects'],objects[4:])
        self.assertEqual(self.source._owner_catalog(TENANT,owner,15,lambda:None),{'at':100,'objects':[],'nextPage':None})
        self.assertNotIn(OBJECT,json.dumps(first))
        self.assertNotIn(foreign,json.dumps(first))
        self.ids['owner']='different-owner'
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None)['objects'],[])

    def test_owner_catalog_rejects_scope_bounds_cancellation_and_rollback(self):
        owner,objects=self.catalog_fixture()
        for tenant,writer,page in [('other',owner,0),(TENANT,'bad',0),(TENANT,owner[:-1]+'V',0),
                                  (TENANT,owner,True),(TENANT,owner,-1),(TENANT,owner,16)]:
            with self.assertRaises(AdmissionRejected):self.source._owner_catalog(tenant,writer,page,lambda:None)
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):self.source._owner_catalog(TENANT,owner,0,cancel)
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)
        self.now=100
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(objects[0],))
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)

    def test_deletion_blocks_delivery_mutations_policy_restore_and_reallocation(self):
        self.ready();permit=self.permit()
        draft=self.source.deletion_view(TENANT,'owner',OBJECT)
        self.assertEqual(draft['claims']['objectVersion'],self.source.read_view(OBJECT,self.now)['objectVersion'])
        verifier=Mock();verifier.matches_deletion.return_value=True
        proof={'deletionBytes':'fixture','signature':'fixture'}
        command=self.source.delete(TENANT,'owner',OBJECT,self.now,proof,verifier=verifier)
        expected=json.loads(verifier.matches_deletion.call_args.args[1])
        self.assertEqual(expected,{**draft['claims'],'ownerPub':'owner-key'})
        for operation in [lambda:self.permit(),lambda:self.source.commit(permit),
                lambda:self.source.read_view(OBJECT,self.now),
                lambda:self.mutate('status',{}),
                lambda:self.source.provision(OBJECT,{},10000,exclusive_grant=lambda *args:True)]:
            with self.assertRaises((AdmissionRejected,HistoryConflict)):operation()
        with self.store._transaction(write=False) as db:
            revision,document=db.execute('SELECT revision,document FROM media_sources WHERE object=?',(OBJECT,)).fetchone()
        self.assertEqual(json.loads(document)['policyUntil'],0)
        with self.assertRaises(AdmissionRejected):
            self.source.replace_policy(OBJECT,revision,{},10000,authorize=lambda *args:True)
        self.now+=120
        self.assertEqual(self.source.delete(TENANT,'owner',OBJECT,100,proof,verifier=verifier),command)
        verifier.matches_deletion.assert_called_once()
        for writer,held in [('reader',proof),('owner',{'deletionBytes':'other','signature':'fixture'})]:
            with self.assertRaises(HistoryConflict):self.source.delete(TENANT,writer,OBJECT,100,held,verifier=verifier)

    def test_deletion_refuses_signature_scope_change_and_cancelled_commit(self):
        verifier=Mock();verifier.matches_deletion.return_value=False
        with self.assertRaises(AdmissionRejected):self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)
        self.source.read_view(OBJECT,self.now)
        for tenant,writer in [('other','owner'),(TENANT,'reader')]:
            with self.assertRaises(AdmissionRejected):self.source.deletion_view(tenant,writer,OBJECT)
            with self.assertRaises(AdmissionRejected):self.source.delete(tenant,writer,OBJECT,self.now,{},verifier=verifier)
        def cancelled(*args,**kwargs):
            self.now+=10
            return True
        verifier.matches_deletion.side_effect=cancelled
        with self.assertRaises(HistoryConflict):self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)
        self.now=100
        self.source.read_view(OBJECT,self.now)
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(OBJECT,))
        with self.assertRaises(AdmissionRejected):self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)

    def test_deletion_binds_fence_and_rejects_primary_rollback(self):
        draft=self.source.deletion_view(TENANT,'owner',OBJECT)
        expected={**draft['claims'],'ownerPub':'owner-key'}
        verifier=Mock();verifier.matches_deletion.side_effect=lambda p,e,**kw:json.loads(e)==expected
        self.mutate('grant',self.grant())
        with self.assertRaises(AdmissionRejected):self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)
        fresh=self.source.deletion_view(TENANT,'owner',OBJECT)
        expected={**fresh['claims'],'ownerPub':'owner-key'}
        with self.store._transaction(write=False) as db:
            original=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(OBJECT,)).fetchone()
        self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)
        # Restore only primary bytes; independent media checkpoint must refuse.
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=?,nonce=?,document=? WHERE object=?',(*original,OBJECT))
        with self.assertRaises(AdmissionRejected):self.source.read_view(OBJECT,self.now)
        with self.assertRaises(AdmissionRejected):self.source.delete(TENANT,'owner',OBJECT,self.now,{},verifier=verifier)

    def test_both_catalogs_refuse_missing_primary_rows_retained_in_checkpoints(self):
        owner,objects=self.catalog_fixture()
        verifier=Mock();verifier.matches_deletion.return_value=True
        self.source.delete(TENANT,owner,objects[0],self.now,{},verifier=verifier)
        with self.store._transaction(write=True) as db:
            db.execute('DELETE FROM media_sources WHERE object=?',(objects[0],))
        for cleanup in (False,True):
            with self.assertRaises(AdmissionRejected):
                self.source._owner_catalog(TENANT,owner,0,lambda:None,cleanup=cleanup)
        self.assertEqual(self.source._owner_catalog(TENANT,owner,1,lambda:None)['objects'],objects[4:])

    def test_cleanup_catalog_uses_permanent_owner_command_after_policy_expiry(self):
        owner,objects=self.catalog_fixture()
        verifier=Mock();verifier.matches_deletion.return_value=True
        command=self.source.delete(TENANT,owner,objects[0],self.now,{},verifier=verifier)
        self.now=11000
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None,cleanup=True),
            {'at':11000,'objects':[{'object':objects[0],'command':command}],'nextPage':1})
        with self.store._transaction(write=True) as db:
            row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(objects[0],)).fetchone()
            doc=json.loads(row[2]);doc['deletion']['cleanupComplete']=True
            self.source._save(db,objects[0],row,doc)
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None,cleanup=True)['objects'],[])
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(objects[0],))
        with self.assertRaises(AdmissionRejected):
            self.source._owner_catalog(TENANT,owner,0,lambda:None,cleanup=True)

    def test_catalog_skips_verified_tombstones_but_rejects_corruption(self):
        owner,objects=self.catalog_fixture()
        verifier=Mock();verifier.matches_deletion.return_value=True
        self.source.delete(TENANT,owner,objects[0],self.now,{},verifier=verifier)
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None)['objects'],objects[1:4])
        self.assertEqual(self.source._owner_catalog(TENANT,owner,1,lambda:None)['objects'],objects[4:])
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',(objects[0],))
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)

    def test_private_view_and_delivery_commit_share_protected_history(self):
        self.ready(); permit=self.permit()
        self.assertEqual((permit.reader_epub,permit.epoch,permit.revision_id),('reader-epub',1,'b'*64))
        self.assertTrue(self.source.commit(permit))
        with self.assertRaises(HistoryConflict): self.source.commit(permit)
        with self.store._transaction(write=False) as db:
            self.assertEqual(self.source._load(db,OBJECT,self.now)[1]['floor'],1)
        self.assertFalse(self.source.production_ready)
        self.assertFalse(hasattr(self.source,'append'))

    def test_identity_acl_policy_and_wrap_changes_invalidate_delivery(self):
        self.ready(); permit=self.permit()
        self.store.append('reader',0,b'{"kind":"revoke"}')
        with self.assertRaises(HistoryConflict):self.source.commit(permit)
        permit=self.permit(); self.ids['bindings']['reader']['epub']='rotated'
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        self.ids['bindings']['reader']['epub']='reader-epub'
        permit=self.permit(); self.mutate('grant',self.grant(grantRevision=2,stated=0))
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)

    def test_status_and_pending_epoch_fail_closed(self):
        self.ready()
        self.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()
        self.native[3].matches_settled.return_value=True
        self.native[1].matches_status.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()
        self.native[1].matches_status.return_value=True
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.permit()

    def test_restore_of_old_database_is_rejected_by_independent_checkpoint(self):
        self.ready(); backup=self.path.read_bytes()
        self.mutate('grant',self.grant(grantRevision=2,stated=0))
        self.path.write_bytes(backup)
        with self.assertRaises(AdmissionRejected):self.permit()
        restarted=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        with self.assertRaises(AdmissionRejected):restarted.authorize(TENANT,'reader',OBJECT)

    def test_signed_forks_freeze_even_after_cancellation_and_restart(self):
        self.ready()
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(itemCiphertextDigest='9'*64))
        with self.assertRaises(AdmissionRejected):self.permit()
        restarted=MediaSource(self.store,TENANT,clock=lambda:self.now,identities=self.identities,native=self.native)
        with self.assertRaises(AdmissionRejected):restarted.authorize(TENANT,'reader',OBJECT)

    def test_exact_retry_keeps_fence_and_stale_revision_is_refused(self):
        self.mutate('grant',self.grant())
        prior=self.source.read_view(OBJECT,self.now)['fence']
        self.mutate('grant',self.grant())
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],prior)
        self.mutate('grant',self.grant(grantRevision=2))
        self.assertTrue(self.mutate('grant',self.grant()))
        with self.assertRaises(HistoryConflict):self.mutate('grant',self.grant(grantRevision=0))

    def test_old_authenticated_fork_freezes_after_newer_cancellation(self):
        self.ready()
        self.mutate('grant',self.grant(grantRevision=2,stated=0))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(itemCiphertextDigest='9'*64))
        self.mutate('grant',self.grant(grantRevision=3))
        with self.assertRaises(AdmissionRejected):self.permit()
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
        self.assertEqual(doc['frozen'],['reader'])
        self.assertEqual(doc['conflicts'][0]['claims']['grantRevision'],1)

    def test_alternate_valid_signatures_are_not_conflicting_claims(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)['fence']
        alternate=self.grant();alternate['proof']['signature']='alternate-valid-signature'
        self.assertTrue(self.mutate('grant',alternate))
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        self.assertTrue(self.permit())
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('grant',alternate)

    def test_cancellation_capacity_is_reserved_when_live_grants_are_full(self):
        for revision in range(1,65): self.mutate('grant',self.grant(grantRevision=revision))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(grantRevision=65))
        self.mutate('grant',self.grant(grantRevision=65,stated=0))
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(grantRevision=66,stated=0))

    def test_policy_update_and_cancellation_guard_are_rechecked_at_commit(self):
        self.ready(); permit=self.permit()
        with self.store._transaction(write=False) as db: revision=self.source._load(db,OBJECT,self.now)[0][0]
        calls=[]
        def auth(*args): calls.append(1); return len(calls)==1
        with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,revision,{'new':True},500,authorize=auth)
        self.assertTrue(self.source.commit(permit))
        with self.store._transaction(write=False) as db: revision=self.source._load(db,OBJECT,self.now)[0][0]
        permit=self.permit()
        self.source.replace_policy(OBJECT,revision,{'new':True},500,authorize=lambda *args:True)
        with self.assertRaises(HistoryConflict):self.source.commit(permit)
        calls=[]
        def cancel():
            calls.append(1)
            if len(calls)>1:raise HistoryConflict('cancelled')
        with self.assertRaises(HistoryConflict):self.mutate('grant',self.grant(grantRevision=2,stated=0),cancel=cancel)
        self.assertTrue(self.permit())

    def test_cross_tenant_subject_timing_and_malformed_mutations_refuse(self):
        self.ready()
        for tenant,reader,object in [('other','reader',OBJECT),(TENANT,'foreign',OBJECT),(TENANT,'reader','media_missing')]:
            with self.assertRaises(AdmissionRejected):self.source.authorize(tenant,reader,object)
        with self.assertRaises(HistoryConflict):
            self.source.mutate(TENANT,'reader',OBJECT,self.now,self.source.read_view(OBJECT,self.now)['fence'],'grant',self.grant())
        for op,payload in [('bad',{}),('grant',{}),('epoch',{}),('wrap',{}),('status',{})]:
            with self.assertRaises(AdmissionRejected):self.mutate(op,payload)
        permit=self.permit(); self.now=permit.expires_at
        with self.assertRaises(AdmissionRejected):self.source.commit(permit)
        with self.assertRaises(AdmissionRejected):self.source.commit(replace(permit,fence='0'*64))

    def test_provision_requires_independent_tenant_and_rechecked_exclusivity(self):
        with self.assertRaises(AdmissionRejected):MediaSource(Mock(require_authority_checkpoint=False),TENANT)
        with self.assertRaises(AdmissionRejected):MediaSource(self.store,'00000000-0000-0000-0000-000000000000',native=self.native)
        with self.assertRaises(AdmissionRejected):MediaSource(self.store,'11234567-89ab-cdef-0123-456789abcdef',native=self.native)
        for object,until in [('foreign',200),(OBJECT,99)]:
            with self.assertRaises(AdmissionRejected):self.source.provision(object,{},until,exclusive_grant=lambda *a:True)
        with self.assertRaises(HistoryConflict):self.source.provision(OBJECT,{},200,exclusive_grant=lambda *a:True)
        calls=[]
        def once(*args):calls.append(1);return len(calls)==1
        with self.assertRaises(AdmissionRejected):self.source.provision('media_new',{},200,exclusive_grant=once)
        with self.assertRaises(AdmissionRejected):self.source.read_view('media_new',self.now)
        with self.assertRaises(AdmissionRejected):self.source.provision('media_large',{'padding':'x'*65536},200,exclusive_grant=lambda *a:True)

    def test_default_identity_loader_uses_all_accounts_from_the_held_transaction(self):
        from history_admission import HistoryAdmission
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,self.now)
            with patch.object(HistoryAdmission,'_run_verifier',return_value=encoded(self.ids)) as run:
                result=self.source._identities(db,OBJECT,doc,self.now)
        self.assertEqual(result,self.ids)
        self.assertEqual(run.call_args.kwargs['mediaObject'],OBJECT)
        self.assertEqual(run.call_args.kwargs['peers'][0]['principal'],'reader')

    def test_rejected_signature_enrollment_and_oversized_mutations_leave_state_unchanged(self):
        before=self.source.read_view(OBJECT,self.now)['fence']
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant())
        self.native[0].matches_grant.return_value=True
        for changes in [{'accessor':'foreign'},{'accessor':[]},{'owner':'foreign'},{'object':'other'}]:
            with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(**changes))
        for value in [{'claims':{},'proof':{}},{**self.grant(),'extra':1},self.grant()|{'proof':{'padding':'x'*17000}}]:
            with self.assertRaises(AdmissionRejected):self.mutate('grant',value)
        with self.assertRaises(AdmissionRejected):self.mutate('grant',{'padding':'x'*65537})
        with self.assertRaises(AdmissionRejected):self.mutate('wrap',{'padding':'x'*4097})
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)

    def test_epoch_signatures_lineage_and_observation_times_are_preserved(self):
        self.mutate('grant',self.grant())
        snapshot=self.source.read_view(OBJECT,self.now)['snapshot']
        document={'manifest':{'epoch':1,'revisionId':'b'*64,'aclSnapshot':'c'*64},'snapshot':snapshot}
        fin={'epoch':1,'revisionId':'b'*64,'previousEpoch':0,'previousFinalizationId':'','finalizationId':'d'*64}
        self.native[2].matches_manifest.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':fin})
        self.native[2].matches_manifest.return_value=True
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':{**fin,'previousEpoch':1}})
        self.native[4].verifies_history.return_value=False
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':document,'finalization':fin})
        self.native[4].verifies_history.return_value=True
        self.mutate('epoch',{'document':document,'finalization':fin})
        with self.assertRaises(HistoryConflict):self.mutate('epoch',{'document':document,'finalization':fin})
        self.now=101
        next_doc={**document,'manifest':{**document['manifest'],'epoch':2,'revisionId':'9'*64}}
        next_fin={**fin,'epoch':2,'revisionId':'9'*64,'previousEpoch':1,'previousFinalizationId':'d'*64,'finalizationId':'8'*64}
        with self.assertRaises(AdmissionRejected):self.mutate('epoch',{'document':next_doc,'finalization':{**next_fin,'previousFinalizationId':'7'*64}})
        self.mutate('epoch',{'document':next_doc,'finalization':next_fin})
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
        self.assertEqual([row['seenAt'] for row in doc['finalizations']],[100000,101000])
        self.assertEqual(doc['anchor'],'d'*64)

    def test_wrap_metadata_cannot_change_recipient_or_item_binding(self):
        self.ready()
        valid={'reader':'reader','record':'e'*64,'digest':'f'*64,'epoch':1,'revisionId':'b'*64,'readerEpub':'reader-epub','itemDigest':'a'*64}
        for field,value in [('reader',[]),('reader','foreign'),('epoch',2),('readerEpub','other'),('itemDigest','9'*64),('record','bad'),('revisionId','9'*64)]:
            with self.assertRaises(AdmissionRejected):self.mutate('wrap',{**valid,field:value})
        with self.assertRaises(AdmissionRejected):self.source.commit(None)
        with self.assertRaises(HistoryConflict):self.source.commit(replace(self.permit(),fence='0'*64))

    def test_policy_refusal_and_expiry(self):
        for until,policy in [(99,{}),(200,{'padding':'x'*60001})]:
            with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,0,policy,until,authorize=lambda *a:True)
        with self.assertRaises(HistoryConflict):self.source.replace_policy(OBJECT,99,{},200,authorize=lambda *a:True)
        with self.assertRaises(AdmissionRejected):self.source.replace_policy(OBJECT,0,{},200,authorize=lambda *a:False)
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.source.read_view(OBJECT,self.now)

    def share_ready(self):
        self.mutate('grant',self.grant(accessor='owner'))
        self.ready()
        self.mutate('wrap',{'reader':'owner','record':'e'*64,'digest':'f'*64,'epoch':1,'revisionId':'b'*64,
                            'readerEpub':'owner-epub','itemDigest':'a'*64})
        self.mutate('status',{'accessor':'owner','signedAt':100000,'maxAgeMs':60000})
        self.ids['bindings']['new']={'pub':'new-key','epub':'new-epub','head':0}

    def share_plan(self,**changes):
        return self.source._owner_share_view(**{'tenant':TENANT,'writer':'owner','object':OBJECT,'reader':'new','cancel':lambda:None,**changes})

    def test_share_plan_preserves_recipients_and_does_not_mutate(self):
        self.share_ready();self.ids['bindings']['unrelated']={'pub':'other','epub':'other','head':0}
        before=self.source.read_view(OBJECT,self.now)
        plan=self.share_plan()
        self.assertEqual(set(plan['bindings']),{'owner','reader','new'})
        self.assertEqual(plan['previousFinalizationId'],'d'*64)
        self.assertEqual(plan['fence'],before['fence'])
        drafts={row['accessor']:row for row in plan['grants']}
        self.assertEqual({row['epoch'] for row in drafts.values()},{2})
        self.assertEqual(drafts['new']['grantRevision'],1)
        self.assertEqual(drafts['new']['from'],100000)
        self.assertEqual(drafts['owner']['grantRevision'],2)
        self.assertEqual(drafts['reader']['grantRevision'],2)
        self.assertEqual([row['accessor'] for row in plan['snapshot']['entries']],['new','owner','reader'])
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        self.mutate('grant',self.grant(**{'grantRevision':2,'from':200000}))
        self.assertEqual(next(row for row in self.share_plan()['grants'] if row['accessor']=='reader')['from'],200000)

    def test_share_plan_requires_owner_delivery_enrollment_and_unfrozen_grants(self):
        self.share_ready()
        for changes in ({'tenant':'other'},{'reader':'owner'},{'reader':'unknown'},{'writer':'reader'},{'reader':[]}):
            with self.assertRaises(AdmissionRejected):self.share_plan(**changes)
        self.native[1].matches_status.return_value=False
        with self.assertRaises(AdmissionRejected):self.share_plan()
        self.native[1].matches_status.return_value=True
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(itemCiphertextDigest='c'*64))
        with self.assertRaises(AdmissionRejected):self.share_plan()

    def test_share_plan_renews_cancelled_target_and_refuses_capacity(self):
        self.share_ready()
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        target=next(row for row in self.share_plan(reader='reader')['grants'] if row['accessor']=='reader')
        self.assertEqual((target['grantRevision'],target['stated'],target['from']),(3,1,100000))
        for revision in range(3,64):self.mutate('grant',self.grant(grantRevision=revision))
        with self.assertRaises(AdmissionRejected):self.share_plan()

    def test_share_plan_refuses_exhausted_revision(self):
        self.share_ready()
        self.mutate('grant',self.grant(grantRevision=9007199254740991))
        with self.assertRaises(AdmissionRejected):self.share_plan()

    def test_share_plan_does_not_shorten_future_grants_into_invalid_intervals(self):
        self.share_ready()
        self.mutate('grant',self.grant(**{'grantRevision':2,'from':200000,'until':300000}))
        with self.store._transaction(write=False) as db:
            revision=db.execute('SELECT revision FROM media_sources WHERE object=?',(OBJECT,)).fetchone()[0]
        self.source.replace_policy(OBJECT,revision,{},150,authorize=lambda *args:True)
        with self.assertRaises(AdmissionRejected):self.share_plan()

    def test_share_reconciliation_checks_owner_signature_and_never_mutates(self):
        self.share_ready()
        payload=self.grant(epoch=2,grantRevision=2)
        before=self.source.read_view(OBJECT,self.now)
        args=(TENANT,'owner',OBJECT,'grant',payload,lambda:None)
        self.assertEqual(self.source._owner_share_state(*args),{'at':100,'state':'absent'})
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        with self.assertRaises(AdmissionRejected):self.source._owner_share_state(TENANT,'reader',OBJECT,'grant',payload,lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._owner_share_state('other','owner',OBJECT,'grant',payload,lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._owner_share_state(TENANT,'owner',OBJECT,'grant',self.grant(object='other',epoch=2,grantRevision=2),lambda:None)
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.source._owner_share_state(*args)

    def test_share_reconciliation_reports_stale_wrap_conflicts_before_publication_checks(self):
        self.share_ready()
        payload={'reader':'reader','record':'e'*64,'digest':'f'*64,'epoch':2,'revisionId':'b'*64,
                 'readerEpub':'reader-epub','itemDigest':'a'*64}
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        self.assertEqual(self.source._owner_share_state(TENANT,'owner',OBJECT,'wrap',payload,lambda:None),{'at':100,'state':'conflict'})
        self.mutate('grant',self.grant(epoch=3,grantRevision=3))
        self.assertEqual(self.source._owner_share_state(TENANT,'owner',OBJECT,'wrap',payload,lambda:None),{'at':100,'state':'conflict'})

    def test_share_check_fence_rejects_intervening_changes_without_freezing_recipient(self):
        self.share_ready();payload=self.grant(epoch=2,grantRevision=2)
        check=self.source._owner_share_check(TENANT,'owner',OBJECT,'grant',payload,lambda:None)
        self.assertEqual(check['state'],'absent')
        self.assertEqual(check['fence'],self.source.read_view(OBJECT,self.now)['fence'])
        self.mutate('grant',self.grant(epoch=2,grantRevision=2,until=9998000))
        with self.assertRaises(HistoryConflict):
            self.source.mutate(TENANT,'owner',OBJECT,check['at'],check['fence'],'grant',payload)
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,self.now)
            self.assertEqual(doc['frozen'],[])

    def test_unshare_plan_cancels_target_and_prepares_remaining_reader_epoch(self):
        self.share_ready();before=self.source.read_view(OBJECT,self.now)
        plan=self.source._owner_unshare_view(TENANT,'owner',OBJECT,'reader',lambda:None)
        self.assertEqual(set(plan['bindings']),{'owner'})
        drafts={g['accessor']:g for g in plan['grants']}
        self.assertEqual((drafts['reader']['stated'],drafts['reader']['grantRevision'],drafts['reader']['epoch']),(0,2,2))
        self.assertEqual((drafts['owner']['stated'],drafts['owner']['epoch']),(1,2))
        self.assertEqual(drafts['reader']['until'],self.grant()['claims']['until'])
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        with self.assertRaises(AdmissionRejected):self.source._owner_unshare_view(TENANT,'owner',OBJECT,'new',lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._owner_unshare_view(TENANT,'owner',OBJECT,'owner',lambda:None)
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        with self.assertRaises(AdmissionRejected):self.source._owner_unshare_view(TENANT,'owner',OBJECT,'reader',lambda:None)

    def test_epoch_context_is_read_only_and_hides_unrelated_identities(self):
        self.ready()
        self.ids['bindings']['unrelated']={'pub':'other','epub':'other','head':0}
        before=self.source.read_view(OBJECT,self.now)
        context=self.source._owner_epoch_view(TENANT,'owner',OBJECT,lambda:None)
        self.assertEqual(context['previousEpoch'],1)
        self.assertEqual(context['previousFinalizationId'],'d'*64)
        self.assertEqual(context['snapshot'],before['snapshot'])
        self.assertEqual(context['fence'],before['fence'])
        self.assertEqual(context['ownerPub'],'owner-key')
        self.assertEqual(set(context['bindings']),{'owner','reader'})
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        with self.assertRaises(HistoryConflict):
            self.source.mutate(TENANT,'owner',OBJECT,self.now,context['fence'],'grant',self.grant(grantRevision=3))

    def test_epoch_context_refuses_missing_settlement_owner_tenant_and_cancel(self):
        def context(tenant=TENANT,writer='owner',cancel=lambda:None):
            return self.source._owner_epoch_view(tenant,writer,OBJECT,cancel)
        with self.assertRaises(AdmissionRejected):context()
        self.ready()
        for values in [{'tenant':'other'},{'writer':'reader'}]:
            with self.assertRaises(AdmissionRejected):context(**values)
        self.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):context()
        self.native[3].matches_settled.return_value=True
        with patch.object(self.source,'_selected_finalization',return_value={'epoch':9007199254740991}):
            with self.assertRaises(AdmissionRejected):context()
        def cancelled():raise AdmissionRejected('cancelled')
        with self.assertRaises(AdmissionRejected):context(cancel=cancelled)

    def test_epoch_parent_survives_grant_change_without_authorizing_old_reads(self):
        self.ready()
        previous=self.source.read_view(OBJECT,self.now)['snapshot']
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        self.native[3].matches_settled.side_effect=lambda raw:json.loads(raw)['current']==previous
        context=self.source._owner_epoch_view(TENANT,'owner',OBJECT,lambda:None)
        self.assertEqual(context['previousFinalizationId'],'d'*64)
        self.assertEqual(context['snapshot']['entries'][0]['stated'],0)
        with self.store._transaction(write=False) as db:
            _,doc=self.source._load(db,OBJECT,self.now)
            with self.assertRaises(AdmissionRejected):self.source._selected(OBJECT,doc,self.now)

    def test_owner_view_restricts_identity_inventory_and_requires_fixed_owner(self):
        view=self.source._owner_view(TENANT,'owner',OBJECT,lambda:None)
        self.assertEqual(set(view['bindings']),{'owner'})
        self.assertEqual(view['at'],self.now)
        self.mutate('grant',self.grant())
        self.assertEqual(set(self.source._owner_view(TENANT,'owner',OBJECT,lambda:None)['bindings']),{'owner','reader'})
        with self.assertRaises(AdmissionRejected):self.source._owner_view(TENANT,'reader',OBJECT,lambda:None)
        with self.assertRaises(AdmissionRejected):self.source._owner_view('other','owner',OBJECT,lambda:None)

    def write_metadata(self, digest='1'*64):
        return {'reader':'reader','record':digest,'digest':digest,'epoch':1,'revisionId':'b'*64,
                'readerEpub':'reader-epub','itemDigest':'a'*64}

    def cancel_view(self, **changes):
        args=dict(tenant=TENANT,writer='owner',object=OBJECT,reader='reader',cancel=lambda:None)
        args.update(changes)
        return self.source._owner_cancel_view(**args)

    def test_cancellation_draft_preserves_claims_and_current_owner_key_without_writing(self):
        self.mutate('grant',self.grant())
        before=self.source.read_view(OBJECT,self.now)['fence']
        self.ids['bindings']['owner']['pub']='rotated-owner-key'
        draft=self.cancel_view()
        self.assertEqual(draft['grant'],{**self.grant()['claims'],'stated':0,'grantRevision':2})
        self.assertEqual(draft['ownerPub'],'rotated-owner-key')
        self.assertEqual(draft['fence'],before)
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        self.mutate('grant',{'claims':draft['grant'],'proof':{'signature':'new-owner-signature'}})
        with self.assertRaises(AdmissionRejected): self.cancel_view()

    def test_cancellation_draft_refuses_wrong_scope_missing_and_frozen_grants(self):
        with self.assertRaises(AdmissionRejected):self.cancel_view()
        self.mutate('grant',self.grant())
        for args in [{'tenant':'other'},{'writer':'reader'},{'reader':'other'},{'reader':[]}]:
            with self.assertRaises(AdmissionRejected):self.cancel_view(**args)
        with self.assertRaises(AdmissionRejected):self.mutate('grant',self.grant(until=9998000))
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def test_cancellation_draft_preserves_expired_claims_but_refuses_exhausted_revision(self):
        self.mutate('grant',self.grant(until=1))
        self.assertEqual(self.cancel_view()['grant']['until'],1)
        self.mutate('grant',self.grant(grantRevision=9007199254740991))
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def test_cancellation_draft_refuses_cancelled_work_expired_policy_and_checkpoint_tampering(self):
        self.mutate('grant',self.grant())
        with self.assertRaises(AdmissionRejected):
            self.cancel_view(cancel=lambda:(_ for _ in ()).throw(AdmissionRejected('cancelled')))
        self.now=10000
        with self.assertRaises(AdmissionRejected):self.cancel_view()
        self.now=100
        with self.store._transaction(write=True) as db:db.execute('UPDATE media_sources SET revision=revision+1')
        with self.assertRaises(AdmissionRejected):self.cancel_view()

    def status_view(self, **changes):
        args={'tenant':TENANT,'writer':'owner','object':OBJECT,'reader':'reader','cancel':lambda:None}
        args.update(changes)
        return self.source._owner_status_view(**args)

    def test_owner_status_draft_uses_current_settled_state_without_writing(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)
        draft=self.status_view()
        self.assertEqual(draft['fence'],before['fence'])
        self.assertEqual(draft['ownerPub'],'owner-key')
        self.assertEqual(draft['status'],{'object':OBJECT,'epoch':1,'revisionId':'b'*64,
            'accessor':'reader','grantRevision':1,'stated':1,'signedAt':100000,'maxAgeMs':60000,
            'zookie':{'object':OBJECT,'objectVersion':3,'snapshotHash':'c'*64}})
        self.assertEqual(self.source.read_view(OBJECT,self.now),before)
        self.mutate('grant',self.grant(grantRevision=2,until=102500))
        self.assertEqual(self.status_view()['status']['maxAgeMs'],2500)

    def test_status_draft_refuses_unbound_owner_reader_pending_and_changed_grants(self):
        self.ready()
        for args in [{'tenant':'other'},{'writer':'reader'},{'reader':'unknown'},{'reader':[]}]:
            with self.assertRaises(AdmissionRejected):self.status_view(**args)
        self.native[3].matches_settled.return_value=False
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.native[3].matches_settled.return_value=True
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.native[0].matches_grant.return_value=True
        self.mutate('grant',self.grant(grantRevision=2,epoch=2))
        with self.assertRaises(AdmissionRejected):self.status_view()
        self.mutate('grant',self.grant(grantRevision=3,stated=0))
        with self.assertRaises(AdmissionRejected):self.status_view()

    def prepare(self, digest='1'*64, **changes):
        metadata=self.write_metadata(digest);metadata.update(changes)
        return self.source.prepare_write(TENANT,'owner',OBJECT,self.now,
            self.source.read_view(OBJECT,self.now)['fence'],metadata,digest,64)

    def test_write_reservation_survives_failure_and_commit_crosses_seconds_safely(self):
        self.ready();before=self.source.read_view(OBJECT,self.now)['objectVersion']
        permit=self.prepare()
        with self.store._transaction(write=False) as db:
            doc=self.source._load(db,OBJECT,self.now)[1]
            self.assertEqual(len(doc['uploads']),1)
            self.assertEqual(doc['objectVersion'],before)
        self.now+=1
        self.assertTrue(self.source.commit_write(permit))
        current=self.source.read_view(OBJECT,self.now)['objectVersion']
        self.assertEqual(current,before+1)
        # Lost-response reconciliation preserves the already committed version.
        self.assertTrue(self.source.commit_write(self.prepare()))
        self.assertEqual(self.source.read_view(OBJECT,self.now)['objectVersion'],current)

    def test_write_commit_rejects_cancellation_identity_change_and_expiry(self):
        self.ready();permit=self.prepare()
        self.mutate('grant',self.grant(stated=0,grantRevision=2))
        with self.assertRaises(HistoryConflict):self.source.commit_write(permit)
        self.mutate('grant',self.grant(grantRevision=3));permit=self.prepare()
        self.store.append('owner',0,b'identity-change')
        with self.assertRaises(HistoryConflict):self.source.commit_write(permit)
        with self.assertRaises(AdmissionRejected):self.source.commit_write(None)
        self.now=permit.expires_at
        with self.assertRaises(AdmissionRejected):self.source.commit_write(permit)

    def test_all_reserved_bytes_count_toward_per_object_capacity(self):
        self.ready()
        for n in range(128):self.prepare(f'{n:064x}')
        before=self.source.read_view(OBJECT,self.now)['fence']
        with self.assertRaises(AdmissionRejected):self.prepare('f'*64)
        self.assertEqual(self.source.read_view(OBJECT,self.now)['fence'],before)
        # An identical reserved record remains reconcilable at capacity.
        self.assertTrue(self.source.commit_write(self.prepare('0'*64)))

    def test_publication_binding_and_native_owner_signature_refusals(self):
        self.ready()
        for changes in [{'record':'2'*64},{'epoch':True},{'readerEpub':'wrong'}]:
            with self.assertRaises(AdmissionRejected):self.prepare(**changes)
        self.native[0].matches_grant.return_value=False
        with self.assertRaises(AdmissionRejected):self.prepare()


class MediaAuthorityCancellationContracts(IsolatedAsyncioTestCase):
    async def test_async_entrypoints_keep_the_exact_commit_permit(self):
        source=object.__new__(MediaSource);source.slots=asyncio.Semaphore(1)
        source.authorize=Mock(return_value='permit');source.commit=Mock(return_value=True)
        self.assertEqual(await source.authorize_read(TENANT,'reader',OBJECT),'permit')
        self.assertTrue(await source.commit_delivery('permit'))
        self.assertEqual(source.commit.call_args.args[0],'permit')
        self.assertFalse(source.slots.locked())
        source._owner_view=Mock(return_value={'fence':'held'});source.mutate=Mock(return_value=True)
        self.assertEqual(await source.owner_view(TENANT,'owner',OBJECT),{'fence':'held'})
        source._owner_epoch_view=Mock(return_value={'previousEpoch':1})
        self.assertEqual(await source.owner_epoch_view(TENANT,'owner',OBJECT),{'previousEpoch':1})
        self.assertEqual(source._owner_epoch_view.call_args.args[:-1],(TENANT,'owner',OBJECT))
        source._owner_share_view=Mock(return_value={'grants':[]})
        self.assertEqual(await source.owner_share_view(TENANT,'owner',OBJECT,'reader'),{'grants':[]})
        self.assertEqual(source._owner_share_view.call_args.args[:-1],(TENANT,'owner',OBJECT,'reader'))
        self.assertTrue(await source.owner_mutate(TENANT,'owner',OBJECT,100,'fence','grant',{'signed':True}))
        self.assertEqual(source.mutate.call_args.args[:-1],(TENANT,'owner',OBJECT,100,'fence','grant',{'signed':True}))
        source.prepare_write=Mock(return_value='write-permit');source.commit_write=Mock(return_value=True)
        self.assertEqual(await source.prepare_wrap_write(TENANT,'owner',OBJECT,100,'fence',{},'a'*64,1),'write-permit')
        self.assertTrue(await source.commit_wrap_write('write-permit'))
        source.deletion_view=Mock(return_value={'claims':'current'})
        self.assertEqual(await source.owner_deletion_view(TENANT,'owner',OBJECT),{'claims':'current'})
        source.delete=Mock(return_value='a'*64)
        proof={'deletionBytes':'signed','signature':'owner'}
        self.assertEqual(await source.owner_delete(TENANT,'owner',OBJECT,100,proof),'a'*64)
        self.assertEqual(source.delete.call_args.args,(TENANT,'owner',OBJECT,100,proof))
        self.assertIsNot(source.delete.call_args.args[-1],proof)
        self.assertTrue(callable(source.delete.call_args.kwargs['cancel']))
        for invalid in [[],{'oversize':'x'*8192}]:
            with self.assertRaises(AdmissionRejected):await source.owner_delete(TENANT,'owner',OBJECT,100,invalid)
        source._owner_status_view=Mock(return_value={'draft':'current'})
        self.assertEqual(await source.owner_status_view(TENANT,'owner',OBJECT,'reader'),{'draft':'current'})

    async def test_cancelled_worker_keeps_slot_and_refuses_late_commit(self):
        source=object.__new__(MediaSource); source.slots=asyncio.Semaphore(1)
        entered=threading.Event(); release=threading.Event(); committed=[]
        def work(guard):
            entered.set(); release.wait(5); guard(); committed.append(True)
        task=asyncio.create_task(source._work(work))
        try:
            for _ in range(100):
                if entered.is_set():break
                await asyncio.sleep(.01)
            self.assertTrue(entered.is_set())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
            with self.assertRaises(HistoryConflict):await source._work(work)
        finally:release.set()
        for _ in range(100):
            if not source.slots.locked():break
            await asyncio.sleep(.01)
        self.assertFalse(source.slots.locked()); self.assertFalse(committed)


class AllocationConsumptionContracts(MediaSourceContracts):
    def allocation(self):
        from types import SimpleNamespace
        record={'object':'media_new','owner':'owner','issuedAt':100,'sig':'signed'}
        scope=SimpleNamespace(tenant=TENANT,owner='owner',object='media_new',
            ownership_digest=hashlib.sha256(encoded(record)).hexdigest(),
            policy_digest=hashlib.sha256(encoded({})).hexdigest())
        scope.claims=lambda:{'tenant':TENANT,'owner':'owner','object':'media_new'}
        proof=SimpleNamespace(scope=scope,allocation='01234567-89ab-cdef-0123-456789abcdef',issued_at=100,expires_at=200)
        return record,proof

    def consume(self,record,proof,**kwargs):
        return self.source.consume_allocation(TENANT,'owner',record,{},10000,
            verify_grant=kwargs.pop('verify_grant',lambda at:proof),**kwargs)

    def test_registration_confirmation_requires_current_owner_and_allocation_anchors(self):
        record,proof=self.allocation()
        with patch.object(self.source,'_identities',return_value=self.ids):self.consume(record,proof)
        before=self.source.read_view('media_new',self.now)['fence']
        def confirm(tenant=TENANT,writer='owner',object='media_new',candidate=record,cancel=lambda:None):
            return self.source._confirm_registration(tenant,writer,object,candidate,cancel)
        with patch.object(self.source,'_identities',return_value=self.ids) as verify:
            self.assertTrue(confirm())
            self.assertEqual(verify.call_args.args[-1],record)
        self.assertEqual(self.source.read_view('media_new',self.now)['fence'],before)
        for args in [{'tenant':'other'},{'writer':'reader'},{'object':'other'},{'candidate':{}},{'candidate':[]}]:
            with self.assertRaises(AdmissionRejected):confirm(**args)
        with patch.object(self.source,'_identities',return_value={'owner':'other'}):
            with self.assertRaises(AdmissionRejected):confirm()
        with patch.object(self.source,'_identities',side_effect=AdmissionRejected('signature')):
            with self.assertRaises(AdmissionRejected):confirm()
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):confirm(cancel=cancel)
        with self.store._transaction(write=True) as db:
            db.execute('DELETE FROM media_allocations WHERE object=?',('media_new',))
        with self.assertRaises(HistoryConflict):confirm()

    def test_retirement_signer_uses_only_accepted_checkpointed_command(self):
        record,proof=self.allocation()
        with patch.object(self.source,'_identities',return_value=self.ids):self.consume(record,proof)
        signer=Mock(return_value=b'signed retirement')
        def prepare(**kw):
            return self.source.prepare_retirement_request(TENANT,'owner','media_new',sign_request=signer,**kw)
        with self.assertRaises(AdmissionRejected):prepare()
        signer.assert_not_called()
        verifier=Mock();verifier.matches_deletion.return_value=True
        command=self.source.delete(TENANT,'owner','media_new',self.now,{},verifier=verifier)
        self.assertEqual(prepare(),b'signed retirement')
        self.assertEqual(signer.call_args.args[0],{'tenant':TENANT,'object':'media_new','owner':'owner','command':command,'issuedAt':100,'expiresAt':130})
        self.now=11000
        self.assertEqual(prepare(),b'signed retirement')
        self.assertEqual(signer.call_args.args[0]['command'],command)
        self.assertEqual(signer.call_args.args[0]['issuedAt'],11000)
        for tenant,writer,object in [('other','owner','media_new'),(TENANT,'reader','media_new'),(TENANT,'owner','missing')]:
            signer.reset_mock()
            with self.assertRaises(AdmissionRejected):self.source.prepare_retirement_request(tenant,writer,object,sign_request=signer)
            signer.assert_not_called()
        for result in [None,b'',b'x'*4097]:
            signer.return_value=result
            with self.assertRaises(AdmissionRejected):prepare()
        signer.return_value=b'valid'
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):prepare(cancel=cancel)
        signer.side_effect=lambda claims:setattr(self,'now',self.now+1) or b'valid'
        with self.assertRaises(HistoryConflict):prepare()

    def test_retirement_completion_is_exact_checkpointed_and_idempotent(self):
        record,proof=self.allocation()
        with patch.object(self.source,'_identities',return_value=self.ids):self.consume(record,proof)
        def confirm(tenant=TENANT,writer='owner',object='media_new',command='bad',**kw):
            return self.source.confirm_retirement(tenant,writer,object,command,**kw)
        with self.assertRaises(AdmissionRejected):confirm()
        verifier=Mock();verifier.matches_deletion.return_value=True
        command=self.source.delete(TENANT,'owner','media_new',self.now,{},verifier=verifier)
        for args in [{'tenant':'other'},{'writer':'reader'},{'object':'missing'},{'command':'bad'}]:
            with self.assertRaises(AdmissionRejected):confirm(**{'command':command,**args})
        def cancel():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):confirm(command=command,cancel=cancel)
        self.now=11000
        self.assertTrue(confirm(command=command))
        self.assertFalse(confirm(command=command))
        with self.store._transaction(write=True) as db:
            db.execute('DELETE FROM media_allocations WHERE object=?',('media_new',))
        with self.assertRaises(HistoryConflict):confirm(command=command)

    def test_active_capacity_released_only_after_confirmed_cleanup(self):
        self.enable_active_index()
        record,proof=self.allocation()
        with patch.object(self.source,'_identities',return_value=self.ids):self.consume(record,proof)
        for i in range(62):self.source.provision('media_fill_'+str(i),{},10000,exclusive_grant=lambda *args:True)
        def create():self.source.provision('media_next',{},10000,exclusive_grant=lambda *args:True)
        with self.assertRaises(AdmissionRejected):create()
        verifier=Mock();verifier.matches_deletion.return_value=True
        command=self.source.delete(TENANT,'owner','media_new',self.now,{},verifier=verifier)
        with self.assertRaises(AdmissionRejected):create()
        calls=0
        def cancel():
            nonlocal calls
            calls+=1
            if calls==2:raise RuntimeError('cancelled commit')
        with self.assertRaises(RuntimeError):self.source.confirm_retirement(TENANT,'owner','media_new',command,cancel=cancel)
        with self.assertRaises(AdmissionRejected):create()
        self.assertTrue(self.source.confirm_retirement(TENANT,'owner','media_new',command))
        self.assertFalse(self.source.confirm_retirement(TENANT,'owner','media_new',command))
        with self.assertRaises(HistoryConflict):self.source.provision('media_new',{},10000,exclusive_grant=lambda *args:True)
        create()
        with self.store._transaction(write=False) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM freshness.media_active').fetchone(),(64,))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM freshness.media_checkpoints').fetchone(),(65,))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM media_sources').fetchone(),(65,))

    def test_active_index_missing_member_refuses_reads(self):
        self.enable_active_index()
        with self.store._transaction(write=False) as db:db.execute('DELETE FROM freshness.media_active WHERE object=?',(OBJECT,))
        with self.assertRaises(HistoryConflict):self.source.read_view(OBJECT,self.now)

    def test_active_catalog_uses_bounded_pending_set_and_detects_primary_rollback(self):
        owner,objects=self.catalog_fixture();self.enable_active_index()
        with self.store._transaction(write=False) as db:
            db.execute('DELETE FROM freshness.media_active WHERE object=?',(objects[0],))
        self.assertEqual(self.source._owner_catalog(TENANT,owner,0,lambda:None)['objects'],objects[1:5])
        with self.store._transaction(write=False) as db:
            db.execute('DELETE FROM media_sources WHERE object=?',(objects[1],))
        with self.assertRaises(AdmissionRejected):self.source._owner_catalog(TENANT,owner,0,lambda:None)

    def test_retirement_refuses_allocation_or_source_rollback(self):
        record,proof=self.allocation()
        with patch.object(self.source,'_identities',return_value=self.ids):self.consume(record,proof)
        verifier=Mock();verifier.matches_deletion.return_value=True
        self.source.delete(TENANT,'owner','media_new',self.now,{},verifier=verifier)
        signer=Mock(return_value=b'signed')
        with self.store._transaction(write=True) as db:
            db.execute('DELETE FROM media_allocations WHERE object=?',('media_new',))
        with self.assertRaises(HistoryConflict):self.source.prepare_retirement_request(TENANT,'owner','media_new',sign_request=signer)
        signer.assert_not_called()
        with self.store._transaction(write=True) as db:
            db.execute('UPDATE media_sources SET revision=revision+1 WHERE object=?',('media_new',))
        with self.assertRaises(AdmissionRejected):self.source.prepare_retirement_request(TENANT,'owner','media_new',sign_request=signer)
        signer.assert_not_called()

    def test_atomic_allocation_retry_and_primary_rollback(self):
        record,proof=self.allocation();before=self.path.read_bytes()
        with patch.object(self.source,'_identities',return_value=self.ids):
            self.assertTrue(self.consume(record,proof))
            self.assertFalse(self.consume(record,proof))
            self.assertEqual(self.source.read_view('media_new',self.now)['snapshot'],{'entries':[]})
            self.path.write_bytes(before)
            with self.assertRaises(HistoryConflict):self.consume(record,proof)

    def test_cancellation_and_changed_grant_roll_back_all_tables(self):
        record,proof=self.allocation()
        def cancelled():raise AdmissionRejected('cancelled')
        with patch.object(self.source,'_identities',return_value=self.ids):
            with self.assertRaises(AdmissionRejected):self.consume(record,proof,cancel=cancelled)
            verifier=Mock(side_effect=[proof,proof,None])
            with self.assertRaises(AdmissionRejected):self.consume(record,proof,verify_grant=verifier)
            self.assertTrue(self.consume(record,proof))

    def test_mismatched_scope_owner_and_duplicate_object_refuse(self):
        record,proof=self.allocation()
        for name,value in [('tenant','foreign'),('owner','foreign'),('object','foreign'),('policy_digest','wrong'),('ownership_digest','wrong')]:
            old=getattr(proof.scope,name);setattr(proof.scope,name,value)
            with self.assertRaises(AdmissionRejected):self.consume(record,proof)
            setattr(proof.scope,name,old)
        with patch.object(self.source,'_identities',return_value={'owner':'foreign'}):
            with self.assertRaises(AdmissionRejected):self.consume(record,proof)
        with patch.object(self.source,'_identities',return_value=self.ids):
            self.assertTrue(self.consume(record,proof))
            proof.allocation='11234567-89ab-cdef-0123-456789abcdef'
            with self.assertRaises(HistoryConflict):self.consume(record,proof)
        for invalid in [None,{**record,'extra':True},{**record,'owner':'foreign'}]:
            with self.assertRaises(AdmissionRejected):self.consume(invalid,proof)


    def test_source_request_signer_runs_only_after_current_ownership_check(self):
        record,proof=self.allocation();signer=Mock(return_value=b'signed request')
        with patch.object(self.source,'_identities',return_value=self.ids):
            result=self.source.prepare_allocation_request(TENANT,'owner',record,{},10000,sign_request=signer)
            self.assertEqual(result,b'signed request')
            self.assertEqual(signer.call_args.args[0],{'tenant':TENANT,'owner':'owner','object':'media_new',
                'policyDigest':proof.scope.policy_digest,'ownershipDigest':proof.scope.ownership_digest,
                'issuedAt':100,'expiresAt':130})
            with self.assertRaises(AdmissionRejected):self.source.read_view('media_new',100)
        signer.reset_mock()
        with patch.object(self.source,'_identities',side_effect=AdmissionRejected('retired key')):
            with self.assertRaises(AdmissionRejected):
                self.source.prepare_allocation_request(TENANT,'owner',record,{},10000,sign_request=signer)
        signer.assert_not_called()
        with patch.object(self.source,'_identities',return_value=self.ids):
            with self.assertRaises(AdmissionRejected):
                self.source.prepare_allocation_request(TENANT,'owner',record,{},10000,sign_request=lambda _:b'')


class ProvisionedMediaStartupContracts(TestCase):
    def test_existing_source_startup_is_read_only_and_checks_all_tables(self):
        from contextlib import contextmanager
        queries=[]
        db=Mock()
        def execute(sql, *args):
            queries.append(sql)
            result=Mock();result.fetchone.return_value=(TENANT,)
            return result
        db.execute.side_effect=execute
        @contextmanager
        def transaction(**options):
            self.assertEqual(options, {'write': False})
            yield db
        store=Mock(require_authority_checkpoint=True, provisioned_media=True, tenant=TENANT)
        store._transaction=transaction
        MediaSource(store,TENANT,identities=Mock(),native=tuple(Mock() for _ in range(5)))
        self.assertEqual(len(queries),5)
        self.assertTrue(all(sql.startswith('SELECT ') for sql in queries))
        store.tenant='11111111-1111-4111-8111-111111111111'
        with self.assertRaises(AdmissionRejected):
            MediaSource(store,TENANT,identities=Mock(),native=tuple(Mock() for _ in range(5)))
