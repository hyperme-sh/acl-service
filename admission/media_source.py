"""Protected direct-media authority, sharing identity and independent checkpoints."""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from uuid import UUID

from statement_source import StatementSource, encoded
from history_admission import HistoryAdmission, _record, _peer_inputs
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.domain.private_wrap_delivery import WrapReadPermit
from acl_service.domain.private_wrap_publication import WrapWritePermit
from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.domain.media_checkpoint import media_checkpoint_digest
from acl_service.infrastructure.epoch_verifier import (
    PrivateGrantVerifier, EpochStatusVerifier, EpochManifestVerifier,
    SettledEpochVerifier, EpochHistoryVerifier, GroupEpochConfigVerifier,
)


class MediaSource:
    """Only new exclusively admitted objects; no import or implicit enrollment.

    This initial source supports direct private grants. Group snapshots refuse.
    Every write and floor commit uses the same attached-database transaction as
    identity history. Operator policy changes require an explicit authorizer.
    """
    def __init__(self, store, tenant, *, clock=time.time, identities=None, native=None):
        if not store.require_authority_checkpoint:
            raise AdmissionRejected('independent authority checkpoint required')
        self.store,self.clock=store,clock
        self.tenant=str(UUID(tenant))
        if self.tenant!=tenant or not UUID(tenant).int: raise AdmissionRejected('canonical media tenant required')
        self.identities = identities or self._identities
        self.native = native or (PrivateGrantVerifier(), EpochStatusVerifier(), EpochManifestVerifier(),
                                 SettledEpochVerifier(), EpochHistoryVerifier())
        self.production_ready = identities is None and native is None
        self.slots = asyncio.Semaphore(1)
        if getattr(store, 'provisioned_media', False):
            with store._transaction(write=False) as db:
                if store.tenant != tenant or db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone() != (tenant,):
                    raise AdmissionRejected('database belongs to another tenant')
                # A missing table must fail startup, never recreate lost state.
                for table in ('media_sources', 'media_allocations', 'freshness.media_checkpoints', 'freshness.media_allocations'):
                    db.execute(f'SELECT 1 FROM {table} LIMIT 1')
            return
        with store._transaction(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS statement_tenant (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO statement_tenant VALUES(1,?)',(tenant,))
            if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone()!=(tenant,):
                raise AdmissionRejected('database belongs to another tenant')
            db.execute('CREATE TABLE IF NOT EXISTS media_sources (object TEXT PRIMARY KEY, revision INTEGER NOT NULL, nonce BLOB NOT NULL, document BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS freshness.media_checkpoints (object TEXT PRIMARY KEY, digest BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS media_allocations (allocation TEXT PRIMARY KEY, object TEXT UNIQUE NOT NULL, digest BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS freshness.media_allocations (allocation TEXT PRIMARY KEY, object TEXT UNIQUE NOT NULL, digest BLOB NOT NULL)')

    _guard=StatementSource._guard
    _accounts=StatementSource._accounts
    _digest=staticmethod(StatementSource._digest)
    _fence=StatementSource._fence

    def _identities(self, db, object, doc, at, record=None):
        accounts = self._accounts(db)
        principal = next(iter(accounts)); account = accounts[principal]
        runner = HistoryAdmission(self.store, grant_for=lambda _:None,
                                  trust_at=lambda _:doc['policy'], clock=self.clock)
        return json.loads(runner._run_verifier(principal, at, mediaObject=object, mediaRecord=record,
            genesis=_record(account.genesis), entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal, accounts)))

    def _group_projection(self, db, object, doc, at, predicate, set_id, rows):
        accounts=self._accounts(db)
        principal=next(iter(accounts)); account=accounts[principal]
        runner=HistoryAdmission(self.store, grant_for=lambda _:None,
                                trust_at=lambda _:doc['policy'], clock=self.clock)
        return json.loads(runner._run_verifier(principal,at,
            genesis=_record(account.genesis),entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal,accounts),
            groupGraph={'object':object,'predicate':predicate,'set':set_id,'rows':rows}))

    def _group_object_projection(self,db,object,doc,at):
        scopes=[]
        for key,rows in sorted(doc.get('groupScopes',{}).items()):
            predicate,_,set_id=key.partition(':')
            scopes.append({'predicate':predicate,'set':set_id,'rows':rows})
        if not scopes:return None
        accounts=self._accounts(db)
        principal=next(iter(accounts));account=accounts[principal]
        runner=HistoryAdmission(self.store,grant_for=lambda _:None,
                                trust_at=lambda _:doc['policy'],clock=self.clock)
        return json.loads(runner._run_verifier(principal,at,
            genesis=_record(account.genesis),entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal,accounts),groupObjectGraph={'object':object,'scopes':scopes}))

    def group_object_view(self,tenant,writer,object,at,cancel=lambda:None):
        """Resolve every retained group scope under one current transaction."""
        self._guard(at,cancel)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner']:raise AdmissionRejected('group owner required')
            return {'projection':self._group_object_projection(db,object,doc,at),
                    'fence':self._fence(db,object,row,at),'objectVersion':doc['objectVersion']}

    def group_authority_view(self,tenant,writer,object,at,cancel=lambda:None):
        """Read preparation inputs together; neither snapshot grants delivery."""
        self._guard(at,cancel)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner']:raise AdmissionRejected('group owner required')
            direct=self._snapshot(doc)
            projection=self._group_object_projection(db,object,doc,at)
            policy=None
            named={writer}|{entry['accessor'] for entry in direct['entries']}
            if projection and projection['snapshot'] is not None:
                edge=projection['snapshot']['objectSet']
                context=self._group_policy_context(db,object,doc,at,edge['predicate'],edge['setId'])
                policy={'context':context,'config':self._selected_group_policy(doc,context)}
                named.add(context['owner'])
                named.update(member['accessor'] for member in projection['snapshot']['members'])
            if not named.issubset(identities['bindings']):
                raise AdmissionRejected('group identity unavailable')
            return {'direct':direct,'projection':projection,'policy':policy,'owner':writer,
                    'bindings':{who:identities['bindings'][who] for who in sorted(named)},
                    'objectVersion':doc['objectVersion'],'fence':self._fence(db,object,row,at)}

    def group_consent_view(self,tenant,member,object,at,predicate,set_id,cancel=lambda:None,*,withdraw=False):
        """Prepare this member's response under the current protected source fence."""
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if member not in identities['bindings']:raise AdmissionRejected('group member unavailable')
            consent=self._group_member_context(db,object,doc,at,predicate,set_id,member,withdraw)
            if consent['memberPub']!=identities['bindings'][member]['pub']:
                raise AdmissionRejected('group member key changed')
            return {'consent':consent,'fence':self._fence(db,object,row,at)}

    def _group_member_context(self,db,object,doc,at,predicate,set_id,member,withdraw=False):
        key=self._group_key(predicate,set_id)
        rows=doc.get('groupScopes',{}).get(key)
        if not rows:raise AdmissionRejected('group invitation unavailable')
        accounts=self._accounts(db)
        principal=next(iter(accounts));account=accounts[principal]
        runner=HistoryAdmission(self.store,grant_for=lambda _:None,
                                trust_at=lambda _:doc['policy'],clock=self.clock)
        graph={'member':member,'object':object,'predicate':predicate,'set':set_id,'rows':rows}
        return json.loads(runner._run_verifier(principal,at,
            genesis=_record(account.genesis),entries=[_record(entry) for entry in account.entries],
            peers=_peer_inputs(principal,accounts),**{'groupWithdrawalGraph' if withdraw else 'groupConsentGraph':graph}))

    @staticmethod
    def _member_group_row(row,member,predicate,set_id):
        if type(row) is not dict or set(row)!={'kind','soul','record'} or row['kind']!='membership':
            raise AdmissionRejected('invalid member row')
        record=row['record']
        if (type(record) is not dict or set(record)!={'role','predicate','set','member','setOwner','stated','hamState','issuedAt','cancels','sig'}
                or record['role']!='member' or record['member']!=member or record['predicate']!=predicate or record['set']!=set_id
                or type(record['stated']) is not int or record['stated'] not in (0,1)
                or type(record['sig']) is not str or not 1<=len(record['sig'])<=128 or len(encoded(row))>8192):
            raise AdmissionRejected('invalid member row')
        return json.loads(encoded(row))

    def member_group_state(self,tenant,member,object,at,predicate,set_id,row,cancel=lambda:None):
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        row=self._member_group_row(row,member,predicate,set_id)
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if member not in identities['bindings']:raise AdmissionRejected('group member unavailable')
            retained=doc.get('groupScopes',{}).get(key)
            if not retained:raise AdmissionRejected('group scope unavailable')
            candidate=self._group_candidate(retained,[row])
            self._group_projection(db,object,doc,at,predicate,set_id,candidate)
            state='applied' if any(encoded(value)==encoded(row) for value in retained) else 'absent'
            return {'state':state,'fence':self._fence(db,object,held,at)}

    def append_member_group(self,tenant,member,object,at,fence,predicate,set_id,row,cancel=lambda:None):
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        row=self._member_group_row(row,member,predicate,set_id)
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if member not in identities['bindings']:raise AdmissionRejected('group member unavailable')
            if type(fence) is not str or not hmac.compare_digest(fence,self._fence(db,object,held,at)):
                raise HistoryConflict('group authority changed')
            retained=doc.get('groupScopes',{}).get(key)
            if not retained:raise AdmissionRejected('group scope unavailable')
            candidate=self._group_candidate(retained,[row])
            self._group_projection(db,object,doc,at,predicate,set_id,candidate)
            if len(candidate)==len(retained):return True
            record=row['record']
            consent=self._group_member_context(db,object,doc,at,predicate,set_id,member,record['stated']==0)
            if consent['memberPub']!=identities['bindings'][member]['pub']:
                raise AdmissionRejected('group member key changed')
            expected={**consent['draft'],'stated':record['stated'],'sig':record['sig']}
            if encoded(expected)!=encoded(record):raise AdmissionRejected('group consent changed')
            if doc['objectVersion']>=9007199254740991:raise AdmissionRejected('object version exhausted')
            doc['objectVersion']+=1
            doc['groupScopes'][key]=candidate
            doc['groupWithdrawalCapacity']=True
            self._save(db,object,held,doc)
        return True

    @staticmethod
    def _group_key(predicate,set_id):
        if predicate not in ('same-group','named-circle') or type(set_id) is not str or not set_id.startswith('set_') or len(set_id)>512:
            raise AdmissionRejected('invalid group scope')
        return predicate+':'+set_id

    def group_view(self,tenant,writer,object,at,predicate,set_id,cancel=lambda:None):
        """Owner-only retained signed rows; this does not grant media access."""
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant: raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner']: raise AdmissionRejected('group owner required')
            rows=doc.get('groupScopes',{}).get(key,[])
            projection=self._group_projection(db,object,doc,at,predicate,set_id,rows) if rows else None
            return {'rows':rows,'projection':projection,'fence':self._fence(db,object,row,at)}

    @staticmethod
    def _group_rows(rows):
        if type(rows) is not list or not 1<=len(rows)<=64 or len(encoded(rows))>65536:
            raise AdmissionRejected('invalid group append')
        return json.loads(encoded(rows))

    @staticmethod
    def _group_candidate(retained,rows):
        candidate=list(retained)
        seen={encoded(item) for item in retained}
        for item in rows:
            key=encoded(item)
            if key not in seen:
                candidate.append(item)
                seen.add(key)
        if len(candidate)>1024 or len(encoded(candidate))>4*1024*1024:
            raise AdmissionRejected('group row capacity')
        return candidate

    def group_append_state(self,tenant,writer,object,at,predicate,set_id,rows,cancel=lambda:None):
        """Reconcile exact signed rows under current authority without writing."""
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        rows=self._group_rows(rows)
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            if writer!=self.identities(db,object,doc,at)['owner']:raise AdmissionRejected('group owner required')
            scopes=doc.get('groupScopes',{})
            if key not in scopes and len(scopes)>=8:raise AdmissionRejected('group scope capacity')
            retained=scopes.get(key,[])
            candidate=self._group_candidate(retained,rows)
            self._group_projection(db,object,doc,at,predicate,set_id,candidate)
            # A batch can legitimately include previously retained object rows.
            # Partial overlap is still absent until every exact row is retained.
            retained_bytes={encoded(item) for item in retained}
            return {'state':'applied' if all(encoded(item) in retained_bytes for item in rows) else 'absent',
                    'fence':self._fence(db,object,held,at)}

    def append_group(self,tenant,writer,object,at,fence,predicate,set_id,rows,cancel=lambda:None):
        """Retain bounded signed group rows in the existing protected media journal.

        Rows are append-only, including cancellations. Native admission checks all
        retained rows against current enrolled histories before the atomic write.
        No epoch, direct grant, wrap or delivery decision is created here.
        """
        self._guard(at,cancel)
        key=self._group_key(predicate,set_id)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        rows=self._group_rows(rows)
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner']: raise AdmissionRejected('group owner required')
            if type(fence) is not str or not hmac.compare_digest(fence,self._fence(db,object,held,at)):
                raise HistoryConflict('group authority changed')
            scopes=doc.setdefault('groupScopes',{})
            if key not in scopes and len(scopes)>=8: raise AdmissionRejected('group scope capacity')
            retained=scopes.get(key,[])
            candidate=self._group_candidate(retained,rows)
            self._group_projection(db,object,doc,at,predicate,set_id,candidate)
            if len(candidate)!=len(retained):
                if doc['objectVersion']>=9007199254740991:raise AdmissionRejected('object version exhausted')
                doc['objectVersion']+=1
                scopes[key]=candidate
                doc['groupWithdrawalCapacity']=True
                self._save(db,object,held,doc)
        return True

    def _group_policy_context(self,db,object,doc,at,predicate,set_id):
        key=self._group_key(predicate,set_id)
        rows=doc.get('groupScopes',{}).get(key)
        if not rows:raise AdmissionRejected('group scope not admitted')
        accounts=self._accounts(db)
        principal=next(iter(accounts));account=accounts[principal]
        runner=HistoryAdmission(self.store,grant_for=lambda _:None,
                                trust_at=lambda _:doc['policy'],clock=self.clock)
        return json.loads(runner._run_verifier(principal,at,
            genesis=_record(account.genesis),entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal,accounts),
            groupPolicyGraph={'object':object,'predicate':predicate,'set':set_id,'rows':rows}))

    @staticmethod
    def _group_policy_digest(config):
        # Same signed transcript as SociACL GroupEpochConfig::digest. Signatures
        # do not affect the deterministic same-revision tie break.
        fields=['s3rch-group-epoch-config-v1',config['owner'],config['setId'],config['predicate'],
                str(config['settleWindowMs']),str(config['configRevision'])]
        return hashlib.sha256(b''.join(len(raw).to_bytes(4,'little')+raw
                                     for raw in (value.encode('utf-8') for value in fields))).hexdigest()

    @staticmethod
    def _group_policy_shape(config):
        if type(config) is not dict or set(config)!={'owner','setId','predicate','settleWindowMs','configRevision','signature'}:
            raise AdmissionRejected('invalid group policy')
        if any(type(config[key]) is not str or not config[key] or len(config[key])>1024
               for key in ('owner','setId','predicate','signature')):
            raise AdmissionRejected('invalid group policy text')
        if type(config['configRevision']) is not int or not 0<=config['configRevision']<=9007199254740991:
            raise AdmissionRejected('invalid group policy revision')
        if type(config['settleWindowMs']) is not int or not 3600000<=config['settleWindowMs']<=259200000:
            raise AdmissionRejected('invalid group policy window')

    def _selected_group_policy(self,doc,context):
        verifier=GroupEpochConfigVerifier()
        valid=[]
        for config in doc.get('groupPolicies',[]):
            if config['setId']!=context['setId'] or config['predicate']!=context['predicate']:continue
            expected={**context,'settleWindowMs':config['settleWindowMs'],'configRevision':config['configRevision']}
            if verifier.matches_config(encoded(config),encoded(expected)):valid.append(config)
        if not valid:return None
        return min(valid,key=lambda config:(-config['configRevision'],self._group_policy_digest(config)))

    def group_policy_view(self,tenant,writer,object,at,predicate,set_id,cancel=lambda:None):
        """Read signed policy under current set-owner history, without granting access."""
        self._guard(at,cancel)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            if writer!=self.identities(db,object,doc,at)['owner']:raise AdmissionRejected('group owner required')
            context=self._group_policy_context(db,object,doc,at,predicate,set_id)
            return {'context':context,'config':self._selected_group_policy(doc,context),
                    'fence':self._fence(db,object,held,at)}

    def append_group_policy(self,tenant,writer,object,at,fence,predicate,set_id,config,cancel=lambda:None):
        """Owner relays a set-owner-signed policy into the protected journal."""
        self._guard(at,cancel)
        if tenant!=self.tenant:raise AdmissionRejected('wrong group tenant')
        self._group_policy_shape(config)
        config=json.loads(encoded(config))
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            held,doc=self._load(db,object,at)
            if writer!=self.identities(db,object,doc,at)['owner']:raise AdmissionRejected('group owner required')
            if type(fence) is not str or not hmac.compare_digest(fence,self._fence(db,object,held,at)):
                raise HistoryConflict('group authority changed')
            context=self._group_policy_context(db,object,doc,at,predicate,set_id)
            expected={**context,'settleWindowMs':config['settleWindowMs'],'configRevision':config['configRevision']}
            if not GroupEpochConfigVerifier().matches_config(encoded(config),encoded(expected)):
                raise AdmissionRejected('group policy signature refused')
            policies=doc.setdefault('groupPolicies',[])
            if config in policies:return True
            if len(policies)>=64:raise AdmissionRejected('group policy capacity')
            if doc['objectVersion']>=9007199254740991:raise AdmissionRejected('object version exhausted')
            policies.append(config)
            doc['objectVersion']+=1
            self._save(db,object,held,doc)
        return True

    def _checkpoint(self, db, object, row, *, write=False):
        digest = media_checkpoint_digest(self.tenant,object,*row)
        if write:
            db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?) ON CONFLICT(object) DO UPDATE SET digest=excluded.digest',(object,digest))
        elif db.execute('SELECT digest FROM freshness.media_checkpoints WHERE object=?',(object,)).fetchone() != (digest,):
            raise AdmissionRejected('media checkpoint mismatch')

    def _capacity(self,db):
        table='freshness.media_active' if getattr(self.store,'active_media_index',False) else 'media_sources'
        if db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]>=64:
            raise AdmissionRejected('media object capacity')

    def _activate(self,db,object):
        if getattr(self.store,'active_media_index',False):
            db.execute('INSERT INTO freshness.media_active VALUES(?)',(object,))

    def _load(self, db, object, at, *, catalog=False):
        row = db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
        if row is None: raise AdmissionRejected('media source unavailable')
        self._checkpoint(db,object,row)
        doc = json.loads(row[2])
        if 'deletion' in doc:
            if catalog: return row,doc  # Only to skip a checkpoint-verified tombstone.
            raise AdmissionRejected('media object deleted')
        if getattr(self.store,'active_media_index',False) and db.execute('SELECT 1 FROM freshness.media_active WHERE object=?',(object,)).fetchone() is None:
            raise HistoryConflict('media active checkpoint missing')
        if at >= doc['policyUntil']: raise AdmissionRejected('media policy expired')
        return row,doc

    @staticmethod
    def _group_withdrawal_capacity(scopes):
        """Reserve canonical stated-0 rows for party assents and object-set edges.

        Rows were natively admitted before storage. HAM ties prefer stated 0;
        signature-byte tie breaks cannot change the reserved stated value.
        A withdrawal need not acknowledge cancellation IDs to remove assent.
        """
        reserve=0
        pending=0
        for rows in scopes.values():
            winners={}
            for envelope in rows:
                kind=envelope.get('kind')
                if kind not in ('membership','object-set'):continue
                record=envelope['record']
                key=(kind,record['predicate'],record['set'],record['member'],record['role']) if kind=='membership' else (kind,record['object'])
                order=(record['hamState'],-record['stated'])
                if key not in winners or order>winners[key][0]:winners[key]=(order,envelope)
            count=0
            for _,envelope in winners.values():
                record=envelope['record']
                if record['stated']!=1:continue
                fields=('role','predicate','set','member','setOwner','hamState') if envelope['kind']=='membership' else ('owner','object','predicate','set','hamState')
                withdrawal={key:record[key] for key in fields}
                withdrawal.update(stated=0,issuedAt=9007199254740991,cancels=[],sig='0'*128)
                reserve+=len(encoded({'kind':envelope['kind'],'soul':envelope['soul'],'record':withdrawal}))+1
                count+=1
            pending+=count
            if len(rows)+count>1024:raise AdmissionRejected('group withdrawal row capacity')
        if len(encoded(scopes))+reserve>512*1024:raise AdmissionRejected('group withdrawal byte capacity')
        return pending

    def _save(self, db, object, row, doc):
        raw=encoded(doc)
        reserve=0
        if doc.get('groupScopes'):
            if len(encoded(doc['groupScopes']))>512*1024: raise AdmissionRejected('aggregate group capacity')
            # New group writes reserve the whole bounded group envelope so later
            # ordinary media writes cannot consume withdrawal space. Existing
            # journals retain their direct-removal budget until a group write
            # can adopt the stronger capacity rule atomically.
            # A direct cancellation payload is at most 16 KiB, plus metadata.
            # Keep all remaining cancellation slots and the deletion tombstone
            # writable even after later ordinary direct-media mutations.
            if 'deletion' not in doc:
                if doc.get('groupWithdrawalCapacity') is True:
                    pending=self._group_withdrawal_capacity(doc['groupScopes'])
                    pending+=sum(entry['stated']==1 for entry in self._snapshot(doc)['entries'])
                    if doc['objectVersion']>9007199254740991-pending:
                        raise AdmissionRejected('withdrawal object version capacity')
                    reserve=512*1024-len(encoded(doc['groupScopes']))
                    reserve+=16-len(str(doc['objectVersion']))
                cancellations=sum(row['claims']['stated']==0 for row in doc['grants'])
                reserve+=max(0,64-cancellations)*17*1024+4096
        if len(raw)+reserve>6*1024*1024: raise AdmissionRejected('media capacity')
        updated=(row[0]+1,row[1],raw)
        db.execute('UPDATE media_sources SET revision=?,nonce=?,document=? WHERE object=?',(*updated,object))
        self._checkpoint(db,object,updated,write=True)

    def provision(self, object, policy, policy_until, *, exclusive_grant):
        at=int(self.clock())
        def guard():
            self._guard(at,lambda:None)
            if not exclusive_grant(self.tenant,object): raise AdmissionRejected('exclusive media grant required')
        if type(object) is not str or not object.startswith('media_') or len(object)>512:
            raise AdmissionRejected('invalid media object')
        if type(policy_until) is not int or policy_until<=at: raise AdmissionRejected('invalid media policy')
        doc={'policy':json.loads(encoded(policy)),'policyUntil':policy_until,'grants':[],
             'manifests':[],'finalizations':[],'statuses':{},'wraps':{},'anchor':'','floor':0,
             'objectVersion':0,'frozen':[],'conflicts':[]}
        guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            self._capacity(db)
            if db.execute('SELECT 1 FROM media_sources WHERE object=?',(object,)).fetchone() or db.execute('SELECT 1 FROM freshness.media_checkpoints WHERE object=?',(object,)).fetchone():
                raise HistoryConflict('media object already provisioned')
            self.identities(db,object,doc,at)
            row=(0,secrets.token_bytes(32),encoded(doc))
            if len(row[2])>65536: raise AdmissionRejected('media policy capacity')
            db.execute('INSERT INTO media_sources VALUES(?,?,?,?)',(object,*row))
            self._checkpoint(db,object,row,write=True)
            self._activate(db,object)

    def prepare_allocation_request(self, tenant, writer, record, policy, policy_until, *,
                                   sign_request, cancel=lambda:None):
        """Authorize a configured source request signer against current history.

        The adapter fixes policy, issuer/source and its private signing key. The
        caller supplies only the canonical ownership record and bound identity.
        No media state is created while preparing this short-lived request.
        """
        at=int(self.clock())
        if (tenant != self.tenant or type(record) is not dict
                or set(record) != {'object','owner','issuedAt','sig'} or record['owner'] != writer
                or type(policy_until) is not int or policy_until<=at):
            raise AdmissionRejected('invalid allocation ownership or policy')
        record=json.loads(encoded(record)); policy=json.loads(encoded(policy))
        if len(encoded(record))>2048 or len(encoded(policy))>65536:
            raise AdmissionRejected('allocation input capacity')
        guard=lambda:self._guard(at,cancel)
        guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            identities=self._identities(db,record['object'],{'policy':policy},at,record)
            if identities['owner'] != writer:
                raise AdmissionRejected('allocation owner mismatch')
            request=sign_request({'tenant':tenant,'object':record['object'],'owner':writer,
                'policyDigest':hashlib.sha256(encoded(policy)).hexdigest(),
                'ownershipDigest':hashlib.sha256(encoded(record)).hexdigest(),
                'issuedAt':at,'expiresAt':min(at+30,policy_until)})
            if type(request) is not bytes or not 1<=len(request)<=4096:
                raise AdmissionRejected('invalid signed allocation request')
            return request

    def consume_allocation(self, tenant, writer, record, policy, policy_until, *,
                           verify_grant, cancel=lambda:None):
        """Consume a configured issuer proof with empty state in one transaction.

        verify_grant(at) is the trusted adapter's bounded signature verifier,
        already bound to configured issuer/source/tenant/policy and raw proof.
        It returns the shared VerifiedAllocation value; it is never request data.
        No source enrollment, policy selection or issuer selection happens here.
        """
        at=int(self.clock())
        if tenant != self.tenant or type(record) is not dict or set(record) != {'object','owner','issuedAt','sig'}:
            raise AdmissionRejected('invalid allocation ownership')
        record=json.loads(encoded(record)); policy=json.loads(encoded(policy))
        if len(encoded(record))>2048 or len(encoded(policy))>65536:
            raise AdmissionRejected('allocation input capacity')
        if record['owner'] != writer or type(policy_until) is not int or policy_until<=at:
            raise AdmissionRejected('invalid allocation owner or policy')
        proof=verify_grant(at)
        scope=proof.scope
        ownership_digest=hashlib.sha256(encoded(record)).hexdigest()
        policy_digest=hashlib.sha256(encoded(policy)).hexdigest()
        if (scope.tenant != tenant or scope.owner != writer or scope.object != record['object']
                or scope.ownership_digest != ownership_digest or scope.policy_digest != policy_digest):
            raise AdmissionRejected('allocation scope mismatch')
        allocation=str(UUID(proof.allocation))
        if allocation != proof.allocation or not UUID(allocation).int:
            raise AdmissionRejected('invalid allocation identifier')
        object=record['object']
        digest=hashlib.sha256(encoded([scope.claims(),allocation,proof.issued_at,proof.expires_at,policy_until])).digest()
        doc={'policy':policy,'policyUntil':policy_until,'grants':[],
             'manifests':[],'finalizations':[],'statuses':{},'wraps':{},'anchor':'','floor':0,
             'objectVersion':0,'frozen':[],'conflicts':[]}
        def guard():
            self._guard(at,cancel)
            if verify_grant(at) != proof:
                raise AdmissionRejected('allocation authority changed')
        guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            # Native verification uses current protected history, including rotation.
            identities=self._identities(db,object,doc,at,record)
            if identities['owner'] != writer:
                raise AdmissionRejected('allocation owner mismatch')
            held=db.execute('SELECT object,digest FROM media_allocations WHERE allocation=?',(allocation,)).fetchone()
            anchor=db.execute('SELECT object,digest FROM freshness.media_allocations WHERE allocation=?',(allocation,)).fetchone()
            if held is not None or anchor is not None:
                if held != (object,digest) or anchor != held:
                    raise HistoryConflict('allocation already consumed or checkpoint mismatch')
                self._load(db,object,at)
                return False
            self._capacity(db)
            for table in ('media_sources','freshness.media_checkpoints','media_allocations','freshness.media_allocations'):
                if db.execute('SELECT 1 FROM '+table+' WHERE object=?',(object,)).fetchone():
                    raise HistoryConflict('media object already provisioned')
            row=(0,secrets.token_bytes(32),encoded(doc))
            if len(row[2])>65536: raise AdmissionRejected('media policy capacity')
            db.execute('INSERT INTO media_sources VALUES(?,?,?,?)',(object,*row))
            self._checkpoint(db,object,row,write=True)
            self._activate(db,object)
            db.execute('INSERT INTO media_allocations VALUES(?,?,?)',(allocation,object,digest))
            db.execute('INSERT INTO freshness.media_allocations VALUES(?,?,?)',(allocation,object,digest))
            return True

    @staticmethod
    def _latest(doc):
        current={}
        for row in doc['grants']:
            claims=row['claims']; accessor=claims['accessor']
            if accessor not in current or claims['grantRevision']>current[accessor]['claims']['grantRevision']:
                current[accessor]=row
        return current

    def _snapshot(self, doc):
        # Direct private grants have no public HAM edge. SociACL requires zero;
        # the signed grantRevision orders the protected journal independently.
        return {'entries':[{'accessor':who,'grantRevision':row['claims']['grantRevision'],
            'stated':row['claims']['stated'],'from':row['claims']['from'],'until':row['claims']['until'],
            'scope':'direct','setId':'','hamState':0}
            for who,row in sorted(self._latest(doc).items())]}

    def _history(self, object, doc, at, fin):
        return {'object':object,'manifests':doc['manifests'],'finalizations':doc['finalizations'],
            'current':self._snapshot(doc),'nowMs':at*1000,'anchorFinalizationId':doc['anchor'],
            'minimumEpoch':doc['floor'],'expectedEpoch':fin['epoch'],'expectedRevisionId':fin['revisionId']}

    def read_view(self, object, at, cancel=lambda:None):
        self._guard(at,cancel)
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            return {'fence':self._fence(db,object,row,at),'snapshot':self._snapshot(doc),
                    'objectVersion':doc['objectVersion'],'owner':identities['owner'],
                    'bindings':identities['bindings']}

    def mutate(self, tenant, writer, object, at, fence, operation, payload, cancel=lambda:None):
        self._guard(at,cancel)
        if tenant!=self.tenant or type(payload) is not dict or len(encoded(payload))>65536:
            raise AdmissionRejected('invalid media mutation')
        payload=json.loads(encoded(payload))
        frozen=False
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner'] or type(fence) is not str or not hmac.compare_digest(fence,self._fence(db,object,row,at)):
                raise HistoryConflict('media authority changed')
            owner_pub=identities['bindings'][writer]['pub']
            if operation=='grant':
                if len(encoded(payload))>16384: raise AdmissionRejected('private grant capacity')
                if set(payload)!={'proof','claims'}: raise AdmissionRejected('invalid grant')
                claims=payload['claims']
                if type(claims) is not dict or set(claims)!={'object','accessor','from','until','stated','epoch','owner','grantRevision','itemCiphertextDigest'}:
                    raise AdmissionRejected('invalid grant claims')
                who=claims['accessor']
                if type(who) is not str or who not in identities['bindings'] or claims['object']!=object or claims['owner']!=writer:
                    raise AdmissionRejected('grant enrollment mismatch')
                if not self.native[0].matches_grant(encoded(payload['proof']),encoded({**claims,'ownerPub':owner_pub})):
                    raise AdmissionRejected('private grant signature refused')
                held=self._latest(doc).get(who)
                retained=next((r for r in doc['grants'] if r['claims']['accessor']==who and r['claims']['grantRevision']==claims['grantRevision']),None)
                if retained:
                    # Authenticated alternate signatures over the same claims are
                    # idempotent, even when a later cancellation is already held.
                    if claims==retained['claims']: return True
                    # An authenticated same-revision fork is permanent, including
                    # when the signed conflict arrived after a cancellation.
                    if who not in doc['frozen']:
                        doc['frozen'].append(who)
                        doc['conflicts'].append({'claims':claims,'proof':payload['proof'],'ownerPub':owner_pub})
                    frozen=True
                else:
                    if held and claims['grantRevision']<held['claims']['grantRevision']:
                        raise HistoryConflict('stale grant revision')
                    stated=claims['stated']
                    if sum(r['claims']['stated']==stated for r in doc['grants'])>=64:
                        raise AdmissionRejected('grant capacity')
                    if stated==0 and (held is None or held['claims']['stated']!=1):
                        raise AdmissionRejected('no live grant to cancel')
                    doc['grants'].append({'claims':claims,'proof':payload['proof'],'ownerPub':owner_pub})
            elif operation=='epoch':
                if set(payload)!={'document','finalization'}: raise AdmissionRejected('invalid epoch')
                document,fin=payload['document'],payload['finalization']
                if type(document) is not dict or type(fin) is not dict: raise AdmissionRejected('invalid epoch')
                manifest=document.get('manifest',{})
                if type(manifest) is not dict or type(fin.get('previousFinalizationId')) is not str:
                    raise AdmissionRejected('invalid epoch shape')
                expected={'ownerPub':owner_pub,'object':object,'epoch':manifest.get('epoch'),'revisionId':manifest.get('revisionId')}
                if not self.native[2].matches_manifest(encoded(document),encoded(expected)) or document['snapshot']!=self._snapshot(doc):
                    raise AdmissionRejected('current manifest refused')
                if any(r['proof']['finalizationId']==fin.get('finalizationId') for r in doc['finalizations']):
                    raise HistoryConflict('finalization already retained')
                if len(doc['manifests'])>=64 or len(doc['finalizations'])>=64: raise AdmissionRejected('epoch capacity')
                parents={r['proof']['finalizationId']:r['proof']['epoch'] for r in doc['finalizations']}
                if not parents:
                    if fin.get('previousEpoch')!=0 or fin.get('previousFinalizationId')!='': raise AdmissionRejected('initial epoch required')
                    doc['anchor']=fin.get('finalizationId')
                elif parents.get(fin.get('previousFinalizationId'))!=fin.get('previousEpoch'):
                    raise AdmissionRejected('unknown epoch parent')
                doc['manifests'].append({'document':document,'expected':expected})
                doc['finalizations'].append({'proof':fin,'ownerPub':owner_pub,'seenAt':at*1000})
                if not self.native[4].verifies_history(encoded(self._history(object,doc,at,fin))):
                    raise AdmissionRejected('epoch history refused')
            elif operation=='wrap':
                self._checked_wrap(doc, identities, payload)
                doc['wraps'][payload['reader']]=payload
            elif operation=='status':
                who=payload.get('accessor')
                grant=self._latest(doc).get(who) if type(who) is str else None
                if not grant: raise AdmissionRejected('unknown status grant')
                self._status(object,doc,grant,payload,owner_pub,at)
                doc['statuses'][who]=payload
            else: raise AdmissionRejected('unknown media operation')
            if operation!='status': doc['objectVersion']+=1
            self._save(db,object,row,doc)
        if frozen: raise AdmissionRejected('private grant fork frozen')
        return True

    def _checked_wrap(self, doc, identities, payload):
        if type(payload) is not dict or len(encoded(payload))>4096:
            raise AdmissionRejected('private wrap capacity')
        required={'reader','record','digest','epoch','revisionId','readerEpub','itemDigest'}
        if (set(payload)!=required or type(payload['reader']) is not str
                or payload['reader'] not in identities['bindings'] or type(payload['epoch']) is not int):
            raise AdmissionRejected('invalid private wrap')
        who=payload['reader']; grant=self._latest(doc).get(who)
        if not grant or grant['claims']['stated']!=1 or payload['epoch']!=grant['claims']['epoch'] or payload['itemDigest']!=grant['claims']['itemCiphertextDigest'] or payload['readerEpub']!=identities['bindings'][who]['epub']:
            raise AdmissionRejected('private wrap binding mismatch')
        import re
        if any(type(payload[k]) is not str or re.fullmatch('[0-9a-f]{64}',payload[k]) is None for k in ('record','digest','revisionId','itemDigest')):
            raise AdmissionRejected('invalid private wrap digest')
        if not any(r['document']['manifest']['revisionId']==payload['revisionId'] and r['document']['manifest']['epoch']==payload['epoch'] for r in doc['manifests']):
            raise AdmissionRejected('unknown wrap epoch')
        return grant

    def _publication_grant(self, doc, identities, owner, metadata, at):
        if owner != identities['owner']:
            raise AdmissionRejected('media owner required')
        grant = self._checked_wrap(doc, identities, metadata)
        claims = grant['claims']
        if metadata['reader'] in doc['frozen'] or not claims['from'] <= at*1000 < claims['until']:
            raise AdmissionRejected('private grant inactive')
        expected = {**claims, 'ownerPub': identities['bindings'][owner]['pub']}
        if not self.native[0].matches_grant(encoded(grant['proof']), encoded(expected)):
            raise AdmissionRejected('private grant owner changed')
        return claims

    def _write_fence(self, db, row, owner, object, digest, length, expires):
        fields=['private-wrap-write-v1',self.tenant,owner,object,digest,length,expires,
                row[0],hashlib.sha256(row[2]).hexdigest(),authority_digest(db).hex()]
        return hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()

    def prepare_write(self, tenant, owner, object, at, fence, metadata, digest, length, cancel=lambda:None):
        self._guard(at,cancel)
        if tenant != self.tenant or type(length) is not int or not 0 < length <= 65536:
            raise AdmissionRejected('invalid private publication')
        metadata=json.loads(encoded(metadata))
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            if type(fence) is not str or not hmac.compare_digest(fence,self._fence(db,object,row,at)):
                raise HistoryConflict('media authority changed')
            identities=self.identities(db,object,doc,at)
            claims=self._publication_grant(doc,identities,owner,metadata,at)
            if metadata['record'] != digest or metadata['digest'] != digest:
                raise AdmissionRejected('private record digest mismatch')
            expires=min(at+3,doc['policyUntil'],claims['until']//1000)
            if expires <= at: raise AdmissionRejected('private publication expired')
            uploads=doc.setdefault('uploads',{})
            reservation={'metadata':metadata,'length':length}
            if digest in uploads:
                if uploads[digest] != reservation: raise HistoryConflict('private reservation changed')
            else:
                if len(uploads) >= 128: raise AdmissionRejected('private publication capacity')
                uploads[digest]=reservation
                # Reservations survive all failures. They do not change signed
                # objectVersion until bytes become the current reader wrap.
                self._save(db,object,row,doc)
                row,_=self._load(db,object,at)
            held=self._write_fence(db,row,owner,object,digest,length,expires)
            return WrapWritePermit(tenant,owner,object,digest,digest,length,held,expires)

    def commit_write(self, permit, cancel=lambda:None):
        at=int(self.clock());self._guard(at,cancel)
        if (type(permit) is not WrapWritePermit or permit.tenant != self.tenant
                or type(permit.expires_at) is not int or permit.expires_at <= at or type(permit.fence) is not str):
            raise AdmissionRejected('invalid private publication permit')
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,permit.object,at)
            held=self._write_fence(db,row,permit.owner,permit.object,permit.digest,permit.length,permit.expires_at)
            if not hmac.compare_digest(held,permit.fence):
                raise HistoryConflict('private publication authority changed')
            reservation=doc.get('uploads',{}).get(permit.record)
            if not reservation or permit.record != permit.digest or reservation['length'] != permit.length:
                raise AdmissionRejected('private reservation unavailable')
            identities=self.identities(db,permit.object,doc,at)
            metadata=reservation['metadata']
            self._publication_grant(doc,identities,permit.owner,metadata,at)
            if doc['wraps'].get(metadata['reader']) == metadata:
                return True
            doc['wraps'][metadata['reader']]=metadata
            doc['objectVersion']+=1
            self._save(db,permit.object,row,doc)
        return True

    def replace_policy(self, object, expected_revision, policy, policy_until, *, authorize):
        at=int(self.clock()); policy=json.loads(encoded(policy))
        if len(encoded(policy))>60000 or type(policy_until) is not int or policy_until<=at:
            raise AdmissionRejected('invalid media policy')
        def guard():
            self._guard(at,lambda:None)
            if not authorize(self.tenant,object,policy,policy_until): raise AdmissionRejected('media policy authorization required')
        guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
            if row is None or row[0]!=expected_revision: raise HistoryConflict('media policy changed')
            self._checkpoint(db,object,row); doc=json.loads(row[2])
            if 'deletion' in doc: raise AdmissionRejected('media object deleted')
            doc.update(policy=policy,policyUntil=policy_until)
            self.identities(db,object,doc,at)
            doc['objectVersion']+=1
            self._save(db,object,row,doc)

    def deletion_view(self, tenant, writer, object, cancel=lambda:None):
        at=int(self.clock());self._guard(at,cancel)
        if tenant!=self.tenant: raise AdmissionRejected('wrong media tenant')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            ids=self.identities(db,object,doc,at)
            if writer!=ids['owner']: raise AdmissionRejected('media owner required')
            claims={'tenant':tenant,'object':object,'owner':writer,'objectVersion':doc['objectVersion'],
                    'fence':self._fence(db,object,row,at),'issuedAt':at*1000,
                    'expiresAt':min(at+60,doc['policyUntil'])*1000}
            return {'at':at,'ownerPub':ids['bindings'][writer]['pub'],'claims':claims}

    def delete(self, tenant, writer, object, at, proof, *, verifier=None, cancel=lambda:None):
        """Persist owner deletion intent before any provider cleanup.

        The trusted adapter supplies the fixed native verifier. No storage is
        contacted and no quota is released here. The original source row and
        independent checkpoint are retained permanently; retries cannot broaden
        the accepted command. Existing readers also refuse policyUntil zero.
        """
        now=int(self.clock());self._guard(now,cancel)
        if tenant!=self.tenant or type(proof) is not dict or len(encoded(proof))>8192:
            raise AdmissionRejected('invalid media deletion')
        proof=json.loads(encoded(proof));proof_digest=hashlib.sha256(encoded(proof)).hexdigest()
        with self.store._transaction(write=True,before_commit=lambda:self._guard(now,cancel)) as db:
            row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
            if row is None: raise AdmissionRejected('media source unavailable')
            self._checkpoint(db,object,row);doc=json.loads(row[2])
            deleted=doc.get('deletion')
            if deleted:
                if writer!=deleted['owner'] or not hmac.compare_digest(proof_digest,deleted['proofDigest']):
                    raise HistoryConflict('different media deletion command')
                return deleted['command']
            self._guard(at,cancel)
            if now>=doc['policyUntil']: raise AdmissionRejected('media policy expired')
            ids=self.identities(db,object,doc,now)
            if writer!=ids['owner']: raise AdmissionRejected('media owner required')
            claims={'tenant':tenant,'object':object,'owner':writer,'objectVersion':doc['objectVersion'],
                    'fence':self._fence(db,object,row,at),'issuedAt':at*1000,
                    'expiresAt':min(at+60,doc['policyUntil'])*1000}
            if verifier is None:
                from acl_service.infrastructure.private_deletion_verifier import PrivateDeletionVerifier
                verifier=PrivateDeletionVerifier()
            if not verifier.matches_deletion(encoded(proof),encoded({**claims,'ownerPub':ids['bindings'][writer]['pub']}),now_ms=now*1000):
                raise AdmissionRejected('media deletion signature refused')
            command=hashlib.sha256(encoded(['private-media-deletion-v1',claims])).hexdigest()
            doc['deletion']={'owner':writer,'command':command,'proofDigest':proof_digest,'claims':claims}
            doc['policyUntil']=0
            doc['objectVersion']+=1
            self._save(db,object,row,doc)
            return command

    def prepare_retirement_request(self, tenant, writer, object, *, sign_request, cancel=lambda:None):
        """Sign only the permanent, checkpointed owner deletion command.

        The trusted adapter supplies the configured source signer. Expired
        delivery policy does not erase an accepted deletion, and this method
        never reconstructs owner consent or changes the stored command.
        """
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if tenant!=self.tenant: raise AdmissionRejected('wrong media tenant')
        with self.store._transaction(write=False,before_commit=guard) as db:
            row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
            if row is None: raise AdmissionRejected('media source unavailable')
            self._checkpoint(db,object,row);doc=json.loads(row[2])
            deleted=doc.get('deletion')
            if not deleted or deleted['owner']!=writer:
                raise AdmissionRejected('accepted owner deletion required')
            held=db.execute('SELECT allocation,digest FROM media_allocations WHERE object=?',(object,)).fetchone()
            anchor=db.execute('SELECT allocation,digest FROM freshness.media_allocations WHERE object=?',(object,)).fetchone()
            if held is None or held!=anchor:
                raise HistoryConflict('retirement allocation checkpoint mismatch')
            request=sign_request({'tenant':tenant,'object':object,'owner':writer,
                'command':deleted['command'],'issuedAt':at,'expiresAt':at+30})
            if type(request) is not bytes or not 1<=len(request)<=4096:
                raise AdmissionRejected('invalid signed retirement request')
            return request

    def confirm_retirement(self, tenant, writer, object, command, cancel=lambda:None):
        """Record a trusted storage completion for the original accepted command."""
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if tenant!=self.tenant: raise AdmissionRejected('wrong media tenant')
        with self.store._transaction(write=True,before_commit=guard) as db:
            row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
            if row is None: raise AdmissionRejected('media source unavailable')
            self._checkpoint(db,object,row);doc=json.loads(row[2])
            deleted=doc.get('deletion')
            if not deleted or deleted['owner']!=writer or deleted['command']!=command:
                raise AdmissionRejected('accepted owner deletion required')
            held=db.execute('SELECT allocation,digest FROM media_allocations WHERE object=?',(object,)).fetchone()
            anchor=db.execute('SELECT allocation,digest FROM freshness.media_allocations WHERE object=?',(object,)).fetchone()
            if held is None or held!=anchor:
                raise HistoryConflict('retirement allocation checkpoint mismatch')
            if deleted.get('cleanupComplete') is True: return False
            deleted['cleanupComplete']=True
            self._save(db,object,row,doc)
            if getattr(self.store,'active_media_index',False):
                if db.execute('DELETE FROM freshness.media_active WHERE object=?',(object,)).rowcount!=1:
                    raise HistoryConflict('media active checkpoint missing')
            return True

    def _selected_finalization(self, object, doc, at, *, historical=False):
        for row in reversed(doc['finalizations']):
            fin=row['proof']
            history=self._history(object,doc,at,fin)
            if historical:
                # Parent preparation authenticates the retained signed snapshot.
                # Delivery must still compare against the current grant snapshot.
                document=next(r['document'] for r in doc['manifests'] if r['document']['manifest']['revisionId']==fin['revisionId'])
                history['current']=document['snapshot']
            if self.native[3].matches_settled(encoded(history)):
                return fin
        raise AdmissionRejected('no current settled epoch')

    def _selected(self, object, doc, at):
        fin=self._selected_finalization(object,doc,at)
        return next(r['document']['manifest'] for r in doc['manifests'] if r['document']['manifest']['revisionId']==fin['revisionId'])

    def _status(self, object, doc, grant, proof, owner_pub, at):
        selected=self._selected(object,doc,at); claims=grant['claims']
        expected={'ownerPub':owner_pub,'object':object,'epoch':selected['epoch'],'revisionId':selected['revisionId'],
            'accessor':claims['accessor'],'grantRevision':claims['grantRevision'],'stated':claims['stated'],
            'zookie':{'object':object,'objectVersion':doc['objectVersion'],'snapshotHash':selected['aclSnapshot']}}
        if claims['epoch']!=selected['epoch'] or not self.native[1].matches_status(encoded(proof),encoded(expected),now_ms=at*1000,skew_ms=0,policy_max_age_ms=60_000):
            raise AdmissionRejected('current epoch status refused')
        return selected

    def _permit(self, db, tenant, reader, object, at, expires=None):
        if tenant!=self.tenant: raise AdmissionRejected('wrong media tenant')
        row,doc=self._load(db,object,at); ids=self.identities(db,object,doc,at)
        grant=self._latest(doc).get(reader); wrap=doc['wraps'].get(reader); status=doc['statuses'].get(reader)
        if reader in doc['frozen'] or not grant or not wrap or not status or reader not in ids['bindings']:
            raise AdmissionRejected('private grant unavailable')
        claims=grant['claims']; owner_pub=ids['bindings'][ids['owner']]['pub']
        if claims['owner']!=ids['owner'] or claims['stated']!=1 or not claims['from']<=at*1000<claims['until']:
            raise AdmissionRejected('private grant inactive')
        if not self.native[0].matches_grant(encoded(grant['proof']),encoded({**claims,'ownerPub':owner_pub})):
            raise AdmissionRejected('private grant owner changed')
        selected=self._status(object,doc,grant,status,owner_pub,at)
        if wrap['epoch']!=selected['epoch'] or wrap['revisionId']!=selected['revisionId'] or wrap['readerEpub']!=ids['bindings'][reader]['epub'] or wrap['itemDigest']!=claims['itemCiphertextDigest']:
            raise AdmissionRejected('private wrap no longer current')
        limit=min(at+2,doc['policyUntil'],claims['until']//1000,(status['signedAt']+min(status['maxAgeMs'],60_000))//1000)
        expires=limit if expires is None else expires
        if type(expires) is not int or not at<expires<=limit: raise AdmissionRejected('private permit expired')
        fields=[tenant,reader,object,wrap['record'],wrap['digest'],selected['epoch'],selected['revisionId'],wrap['readerEpub'],expires]
        fence=hmac.new(row[1],encoded([fields,row[0],hashlib.sha256(row[2]).hexdigest(),authority_digest(db).hex()]),hashlib.sha256).hexdigest()
        permit=WrapReadPermit(tenant,reader,object,wrap['record'],wrap['digest'],selected['epoch'],selected['revisionId'],wrap['readerEpub'],fence,expires)
        return permit,ids,row,doc

    def _reader_catalog(self, tenant, reader, page, cancel):
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if tenant!=self.tenant or type(reader) is not str or type(page) is not int or not 0<=page<16:
            raise AdmissionRejected('invalid media reader catalog')
        objects=[]
        with self.store._transaction(write=False,before_commit=guard) as db:
            candidates='freshness.media_active' if getattr(self.store,'active_media_index',False) else '(SELECT object FROM media_sources UNION SELECT object FROM freshness.media_checkpoints) AS candidates'
            rows=db.execute(f'SELECT object FROM {candidates} ORDER BY object LIMIT 65').fetchall()
            if len(rows)>64:raise AdmissionRejected('media catalog capacity')
            for (object,) in rows:
                guard()
                # Corrupt or missing primary data cannot silently disappear.
                row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
                if row is None:raise AdmissionRejected('media source unavailable')
                self._checkpoint(db,object,row)
                doc=json.loads(row[2])
                # Avoid native work for objects without even a candidate grant.
                if ('deletion' in doc or reader not in doc['wraps'] or reader not in doc['statuses']
                        or reader not in self._latest(doc)):
                    continue
                try:
                    _,ids,_,_=self._permit(db,tenant,reader,object,at)
                except AdmissionRejected:
                    continue  # No current grant/status/wrap: disclose no ID.
                if ids['owner']!=reader:objects.append(object)
            # Filter before pagination: hidden entries never occupy visible slots.
            return {'at':at,'objects':objects[page*4:(page+1)*4],'nextPage':page+1 if page<15 else None}

    async def reader_catalog(self, tenant, reader, page):
        return await self._work(self._reader_catalog,tenant,reader,page)

    def authorize(self, tenant, reader, object, cancel=lambda:None):
        at=int(self.clock()); self._guard(at,cancel)
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            return self._permit(db,tenant,reader,object,at)[0]

    def commit(self, permit, cancel=lambda:None):
        at=int(self.clock()); self._guard(at,cancel)
        if type(permit) is not WrapReadPermit: raise AdmissionRejected('invalid media permit')
        with self.store._transaction(write=True,before_commit=lambda:self._guard(at,cancel)) as db:
            current,ids,row,doc=self._permit(db,permit.tenant,permit.reader,permit.object,at,permit.expires_at)
            if current!=permit: raise HistoryConflict('private delivery authority changed')
            for principal,binding in ids['bindings'].items(): self.store._observe_floor(db,principal,binding['head'])
            if permit.epoch>doc['floor']:
                doc['floor']=permit.epoch; self._save(db,permit.object,row,doc)
        return True

    async def _work(self, function, *args):
        if self.slots.locked(): raise HistoryConflict('media authority busy')
        await self.slots.acquire(); stopped=threading.Event()
        def guard():
            if stopped.is_set(): raise HistoryConflict('media request cancelled')
        work=asyncio.create_task(asyncio.to_thread(function,*args,guard))
        try: return await asyncio.shield(work)
        finally:
            stopped.set()
            if work.done(): self.slots.release()
            else:
                def finished(task):
                    if not task.cancelled(): task.exception()
                    self.slots.release()
                work.add_done_callback(finished)

    async def authorize_read(self, tenant, reader, object):
        return await self._work(self.authorize,tenant,reader,object)

    async def commit_delivery(self, permit):
        return await self._work(self.commit,permit)

    def _owner_view(self, tenant, writer, object, cancel):
        if tenant != self.tenant:
            raise AdmissionRejected('media tenant mismatch')
        at = int(self.clock())
        view = self.read_view(object, at, cancel)
        if writer != view['owner']:
            raise AdmissionRejected('media owner required')
        # An object owner may see its own recipients, not the entire tenant's
        # enrolled identity inventory. Admit a signed grant before wrapping it.
        named = {writer} | {row['accessor'] for row in view['snapshot']['entries']}
        view['bindings'] = {who: binding for who, binding in view['bindings'].items() if who in named}
        self._guard(at, cancel)
        return {'at': at, **view}

    def _confirm_registration(self,tenant,writer,object,record,cancel):
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if (tenant!=self.tenant or type(record) is not dict
                or set(record)!={'object','owner','issuedAt','sig'}
                or record['object']!=object or record['owner']!=writer or len(encoded(record))>2048):
            raise AdmissionRejected('invalid media registration')
        record=json.loads(encoded(record))
        with self.store._transaction(write=False,before_commit=guard) as db:
            _,doc=self._load(db,object,at)
            held=db.execute('SELECT allocation,digest FROM media_allocations WHERE object=?',(object,)).fetchone()
            anchor=db.execute('SELECT allocation,digest FROM freshness.media_allocations WHERE object=?',(object,)).fetchone()
            if held is None or held!=anchor:
                raise HistoryConflict('media allocation checkpoint mismatch')
            identities=self._identities(db,object,doc,at,record)
            if identities['owner']!=writer:
                raise AdmissionRejected('media owner required')
            guard()
            return True

    async def owner_confirm_registration(self,tenant,writer,object,record):
        if type(record) is not dict or len(encoded(record))>2048:raise AdmissionRejected('invalid media registration')
        record=json.loads(encoded(record))
        return await self._work(self._confirm_registration,tenant,writer,object,record)

    def _owner_upload_state(self, tenant, writer, object, operation, payload, cancel):
        from acl_service.domain.media_upload_reconcile import upload_state
        at = int(self.clock()); self._guard(at, cancel)
        if tenant != self.tenant or type(payload) is not dict or len(encoded(payload)) > 81920:
            raise AdmissionRejected('invalid upload intent')
        payload = json.loads(encoded(payload))
        with self.store._transaction(write=False, before_commit=lambda:self._guard(at, cancel)) as db:
            _, doc = self._load(db, object, at)
            identities = self.identities(db, object, doc, at)
            if writer != identities['owner']: raise AdmissionRejected('media owner required')
            latest = self._latest(doc)
            grant = latest.get(writer)
            if grant is not None:
                expected = {**grant['claims'], 'ownerPub': identities['bindings'][writer]['pub']}
                if not self.native[0].matches_grant(encoded(grant['proof']), encoded(expected)):
                    raise AdmissionRejected('private grant owner changed')
            if operation == 'wrap': self._publication_grant(doc, identities, writer, payload, at)
            state = upload_state(doc, latest, self._snapshot(doc), writer, operation, payload)
            self._guard(at, cancel)
            return {'at': at, 'state': state}

    async def owner_upload_state(self, tenant, writer, object, operation, payload):
        return await self._work(self._owner_upload_state, tenant, writer, object, operation, payload)

    def _owner_share_state(self, tenant, writer, object, operation, payload, cancel, *, include_fence=False):
        from acl_service.domain.media_share_reconcile import share_state
        at = int(self.clock()); self._guard(at, cancel)
        if tenant != self.tenant or type(payload) is not dict or len(encoded(payload)) > 81920:
            raise AdmissionRejected('invalid upload intent')
        payload = json.loads(encoded(payload))
        with self.store._transaction(write=False, before_commit=lambda:self._guard(at, cancel)) as db:
            row, doc = self._load(db, object, at)
            identities = self.identities(db, object, doc, at)
            if writer != identities['owner']: raise AdmissionRejected('media owner required')
            latest = self._latest(doc)
            grant = latest.get(writer)
            if grant is not None:
                expected = {**grant['claims'], 'ownerPub': identities['bindings'][writer]['pub']}
                if not self.native[0].matches_grant(encoded(grant['proof']), encoded(expected)):
                    raise AdmissionRejected('private grant owner changed')
            if operation == 'grant':
                claims=payload.get('claims',{})
                if type(claims) is not dict or claims.get('object') != object or type(claims.get('accessor')) is not str or claims['accessor'] not in identities['bindings'] or not self.native[0].matches_grant(encoded(payload.get('proof')),encoded({**claims,'ownerPub':identities['bindings'][writer]['pub']})):
                    raise AdmissionRejected('sharing signature refused')
            state = share_state(doc, latest, self._snapshot(doc), writer, operation, payload)
            if operation == 'wrap' and state != 'conflict':
                target=self._checked_wrap(doc,identities,payload)
                if not self.native[0].matches_grant(encoded(target['proof']),encoded({**target['claims'],'ownerPub':identities['bindings'][writer]['pub']})):
                    raise AdmissionRejected('sharing recipient changed')
            self._guard(at, cancel)
            result={'at': at, 'state': state}
            if include_fence: result['fence']=self._fence(db,object,row,at)
            return result

    async def owner_share_state(self, tenant, writer, object, operation, payload):
        return await self._work(self._owner_share_state, tenant, writer, object, operation, payload)

    def _owner_share_check(self, tenant, writer, object, operation, payload, cancel):
        return self._owner_share_state(tenant,writer,object,operation,payload,cancel,include_fence=True)

    async def owner_share_check(self, tenant, writer, object, operation, payload):
        return await self._work(self._owner_share_check,tenant,writer,object,operation,payload)

    async def owner_view(self, tenant, writer, object):
        return await self._work(self._owner_view, tenant, writer, object)

    def _owner_epoch_view(self, tenant, writer, object, cancel):
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if tenant!=self.tenant: raise AdmissionRejected('media tenant mismatch')
        with self.store._transaction(write=False,before_commit=guard) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer!=identities['owner']: raise AdmissionRejected('media owner required')
            parent=self._selected_finalization(object,doc,at,historical=True)
            if type(parent['epoch']) is not int or not 1<=parent['epoch']<9007199254740991:
                raise AdmissionRejected('media epoch exhausted')
            snapshot=self._snapshot(doc)
            named={writer}|{entry['accessor'] for entry in snapshot['entries']}
            guard()
            return {'at':at,'fence':self._fence(db,object,row,at),'snapshot':snapshot,
                    'owner':writer,'ownerPub':identities['bindings'][writer]['pub'],
                    'previousEpoch':parent['epoch'],'previousFinalizationId':parent['finalizationId'],
                    'bindings':{who:binding for who,binding in identities['bindings'].items() if who in named}}

    async def owner_epoch_view(self, tenant, writer, object):
        return await self._work(self._owner_epoch_view,tenant,writer,object)

    def _owner_share_view(self, tenant, writer, object, reader, cancel, *, remove=False):
        at=int(self.clock());guard=lambda:self._guard(at,cancel)
        guard()
        if tenant!=self.tenant or type(reader) is not str or reader==writer:
            raise AdmissionRejected('invalid media share target')
        with self.store._transaction(write=False,before_commit=guard) as db:
            _,ids,row,doc=self._permit(db,tenant,writer,object,at)
            if writer!=ids['owner'] or reader not in ids['bindings'] or reader in doc['frozen']:
                raise AdmissionRejected('media owner and enrolled recipient required')
            parent=self._selected_finalization(object,doc,at)
            epoch=parent['epoch']
            if type(epoch) is not int or not 1<=epoch<9007199254740991:
                raise AdmissionRejected('media epoch exhausted')
            latest=self._latest(doc);owner_pub=ids['bindings'][writer]['pub']
            owner_claims=latest[writer]['claims'];item=owner_claims['itemCiphertextDigest']
            claims={who:value['claims'] for who,value in latest.items()}
            if remove and (reader not in claims or claims[reader]['stated']!=1):
                raise AdmissionRejected('current recipient grant required')
            targets={reader}|{who for who,value in claims.items() if value['stated']==1 and at*1000<value['until']}
            active_count=len(targets)-(1 if remove else 0)
            if (len(targets)>64 or sum(value['claims']['stated']==1 for value in doc['grants'])+active_count>64
                    or (remove and sum(value['claims']['stated']==0 for value in doc['grants'])>=64)
                    or len(doc['manifests'])>=64 or len(doc['finalizations'])>=64):
                raise AdmissionRejected('media share capacity')
            drafts=[]
            for who in sorted(targets):
                held=claims.get(who)
                if who not in ids['bindings'] or who in doc['frozen']:
                    raise AdmissionRejected('media recipient unavailable')
                if held and (held['owner']!=writer or held['itemCiphertextDigest']!=item
                        or not self.native[0].matches_grant(encoded(latest[who]['proof']),encoded({**held,'ownerPub':owner_pub}))):
                    raise AdmissionRejected('media recipient grant changed')
                revision=held['grantRevision'] if held else 0
                if type(revision) is not int or not 0<=revision<9007199254740991:
                    raise AdmissionRejected('media grant revision exhausted')
                active=held and held['stated']==1 and at*1000<held['until']
                draft={'object':object,'owner':writer,'accessor':who,'from':held['from'] if active else at*1000,
                       'until':min(held['until'] if active else owner_claims['until'],doc['policyUntil']*1000),
                       'stated':1,'epoch':epoch+1,'grantRevision':revision+1,'itemCiphertextDigest':item}
                if remove and who==reader:
                    draft={**held,'epoch':epoch+1,'grantRevision':revision+1,'stated':0}
                if draft['until']<=draft['from']:raise AdmissionRejected('media share policy expires before grant')
                drafts.append(draft);claims[who]=draft
            snapshot=self._snapshot({'grants':[{'claims':value} for value in claims.values()]})
            guard()
            return {'at':at,'fence':self._fence(db,object,row,at),'owner':writer,'ownerPub':owner_pub,
                    'reader':reader,'previousEpoch':epoch,'previousFinalizationId':parent['finalizationId'],
                    'grants':drafts,'snapshot':snapshot,
                    'bindings':{who:ids['bindings'][who] for who in sorted(targets) if not (remove and who==reader)}}

    async def owner_share_view(self, tenant, writer, object, reader):
        return await self._work(self._owner_share_view,tenant,writer,object,reader)

    def _owner_unshare_view(self, tenant, writer, object, reader, cancel):
        return self._owner_share_view(tenant,writer,object,reader,cancel,remove=True)

    async def owner_unshare_view(self, tenant, writer, object, reader):
        return await self._work(self._owner_unshare_view,tenant,writer,object,reader)

    def _owner_catalog(self, tenant, writer, page, cancel, *, cleanup=False):
        if tenant != self.tenant or type(writer) is not str or type(page) is not int or not 0 <= page < 16:
            raise AdmissionRejected('invalid media catalog request')
        if re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}',writer) is None:
            raise AdmissionRejected('invalid media catalog owner')
        coordinates = [base64.b64decode(part+'=',altchars=b'-_',validate=True) for part in writer.split('.')]
        if any(base64.urlsafe_b64encode(raw).decode().rstrip('=') != part for raw,part in zip(coordinates,writer.split('.'))):
            raise AdmissionRejected('invalid media catalog owner')
        prefix = 'media_p_' + b''.join(coordinates).hex() + '_'
        at = int(self.clock()); self._guard(at, cancel)
        objects = []
        with self.store._transaction(write=False, before_commit=lambda:self._guard(at,cancel)) as db:
            # The canonical owner prefix only narrows candidates. Every returned
            # ID still needs current native owner verification. Other owners do
            # not affect page positions or nextPage. Retained checkpoint IDs
            # prevent a primary rollback from silently removing candidates.
            candidates='freshness.media_active' if getattr(self.store,'active_media_index',False) else '(SELECT object FROM media_sources UNION SELECT object FROM freshness.media_checkpoints) AS candidates'
            rows = db.execute(f'SELECT object FROM {candidates} WHERE substr(object,1,?)=? ORDER BY object LIMIT 4 OFFSET ?',
                              (len(prefix),prefix,page*4)).fetchall()
            for (object,) in rows:
                self._guard(at,cancel)
                if cleanup:
                    row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
                    if row is None: raise AdmissionRejected('media source unavailable')
                    self._checkpoint(db,object,row);doc=json.loads(row[2])
                    deleted=doc.get('deletion')
                    if deleted and deleted['owner']==writer and deleted.get('cleanupComplete') is not True:
                        objects.append({'object':object,'command':deleted['command']})
                    continue
                _,doc = self._load(db,object,at,catalog=True)
                if 'deletion' in doc: continue
                identities = self.identities(db,object,doc,at)
                if identities['owner'] == writer:
                    objects.append(object)
            self._guard(at,cancel)
        return {'at':at,'objects':objects,'nextPage':page+1 if page<15 else None}

    async def owner_cleanup_catalog(self, tenant, writer, page):
        return await self._work(lambda cancel:self._owner_catalog(tenant,writer,page,cancel,cleanup=True))

    async def owner_catalog(self, tenant, writer, page):
        return await self._work(self._owner_catalog,tenant,writer,page)

    def _owner_status_view(self, tenant, writer, object, reader, cancel):
        at = int(self.clock()); self._guard(at, cancel)
        if tenant != self.tenant or type(reader) is not str:
            raise AdmissionRejected('invalid media status request')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer != identities['owner']:
                raise AdmissionRejected('media owner required')
            grant=self._latest(doc).get(reader)
            if reader in doc['frozen'] or reader not in identities['bindings'] or not grant:
                raise AdmissionRejected('private grant unavailable')
            claims=grant['claims']; owner_pub=identities['bindings'][writer]['pub']
            if claims['owner']!=writer or claims['stated']!=1 or not claims['from']<=at*1000<claims['until']:
                raise AdmissionRejected('private grant inactive')
            if not self.native[0].matches_grant(encoded(grant['proof']),encoded({**claims,'ownerPub':owner_pub})):
                raise AdmissionRejected('private grant owner changed')
            selected=self._selected(object,doc,at)
            if claims['epoch']!=selected['epoch']:
                raise AdmissionRejected('private grant epoch changed')
            status={'object':object,'epoch':selected['epoch'],'revisionId':selected['revisionId'],
                'accessor':reader,'grantRevision':claims['grantRevision'],'stated':1,
                'signedAt':at*1000,'maxAgeMs':min(60_000,(doc['policyUntil']-at)*1000,claims['until']-at*1000),
                'zookie':{'object':object,'objectVersion':doc['objectVersion'],'snapshotHash':selected['aclSnapshot']}}
            return {'at':at,'fence':self._fence(db,object,row,at),'ownerPub':owner_pub,'status':status}

    async def owner_status_view(self, tenant, writer, object, reader):
        return await self._work(self._owner_status_view,tenant,writer,object,reader)

    def _owner_cancel_view(self, tenant, writer, object, reader, cancel):
        at = int(self.clock()); self._guard(at, cancel)
        if tenant != self.tenant or type(reader) is not str:
            raise AdmissionRejected('invalid media cancellation request')
        with self.store._transaction(write=False,before_commit=lambda:self._guard(at,cancel)) as db:
            row,doc=self._load(db,object,at)
            identities=self.identities(db,object,doc,at)
            if writer != identities['owner']:
                raise AdmissionRejected('media owner required')
            held=self._latest(doc).get(reader)
            if reader in doc['frozen'] or reader not in identities['bindings'] or not held:
                raise AdmissionRejected('private grant unavailable')
            claims=held['claims']
            if claims['owner'] != writer or claims['stated'] != 1:
                raise AdmissionRejected('no live grant to cancel')
            revision=claims['grantRevision']
            if type(revision) is not int or not 1 <= revision < 9007199254740991:
                raise AdmissionRejected('grant revision exhausted')
            # The checkpoint authenticates the already admitted historical grant.
            # A rotated current owner can cancel it without the old private key.
            draft={**claims,'stated':0,'grantRevision':revision+1}
            self._guard(at,cancel)
            return {'at':at,'fence':self._fence(db,object,row,at),
                    'ownerPub':identities['bindings'][writer]['pub'],'grant':draft}

    async def owner_cancel_view(self, tenant, writer, object, reader):
        return await self._work(self._owner_cancel_view,tenant,writer,object,reader)

    async def owner_deletion_view(self, tenant, writer, object):
        return await self._work(self.deletion_view,tenant,writer,object)

    async def owner_delete(self, tenant, writer, object, at, proof):
        if type(proof) is not dict or len(encoded(proof))>8192:
            raise AdmissionRejected('invalid media deletion')
        proof=json.loads(encoded(proof))
        return await self._work(lambda cancel:self.delete(tenant,writer,object,at,proof,cancel=cancel))

    def _owner_group_view(self,tenant,writer,object,cancel):
        at=int(self.clock())
        return {'at':at,**self.group_object_view(tenant,writer,object,at,cancel)}

    def _member_group_consent_view(self,tenant,member,object,predicate,set_id,cancel):
        at=int(self.clock())
        return {'at':at,**self.group_consent_view(tenant,member,object,at,predicate,set_id,cancel)}

    async def member_group_consent_view(self,tenant,member,object,predicate,set_id):
        return await self._work(self._member_group_consent_view,tenant,member,object,predicate,set_id)

    async def member_group_withdrawal_view(self,tenant,member,object,predicate,set_id):
        def read(cancel):
            at=int(self.clock())
            return {'at':at,**self.group_consent_view(tenant,member,object,at,predicate,set_id,cancel,withdraw=True)}
        return await self._work(read)

    async def member_group_append_state(self,tenant,member,object,predicate,set_id,row):
        row=self._member_group_row(row,member,predicate,set_id)
        def read(cancel):
            at=int(self.clock())
            return {'at':at,**self.member_group_state(tenant,member,object,at,predicate,set_id,row,cancel)}
        return await self._work(read)

    async def member_append_group(self,tenant,member,object,at,fence,predicate,set_id,row):
        row=self._member_group_row(row,member,predicate,set_id)
        return await self._work(lambda cancel:self.append_member_group(tenant,member,object,at,fence,predicate,set_id,row,cancel))

    def _owner_group_authority_view(self,tenant,writer,object,cancel):
        at=int(self.clock())
        return {'at':at,**self.group_authority_view(tenant,writer,object,at,cancel)}

    async def owner_group_authority_view(self,tenant,writer,object):
        return await self._work(self._owner_group_authority_view,tenant,writer,object)

    async def owner_group_view(self,tenant,writer,object):
        return await self._work(self._owner_group_view,tenant,writer,object)

    def _owner_group_append_state(self,tenant,writer,object,predicate,set_id,rows,cancel):
        at=int(self.clock())
        return {'at':at,**self.group_append_state(tenant,writer,object,at,predicate,set_id,rows,cancel)}

    async def owner_group_append_state(self,tenant,writer,object,predicate,set_id,rows):
        rows=self._group_rows(rows)
        return await self._work(self._owner_group_append_state,tenant,writer,object,predicate,set_id,rows)

    async def owner_append_group(self,tenant,writer,object,at,fence,predicate,set_id,rows):
        if type(rows) is not list or len(encoded(rows))>65536:raise AdmissionRejected('invalid group append')
        rows=json.loads(encoded(rows))
        return await self._work(self.append_group,tenant,writer,object,at,fence,predicate,set_id,rows)

    def _owner_group_policy_view(self,tenant,writer,object,predicate,set_id,cancel):
        at=int(self.clock())
        return {'at':at,**self.group_policy_view(tenant,writer,object,at,predicate,set_id,cancel)}

    async def owner_group_policy_view(self,tenant,writer,object,predicate,set_id):
        return await self._work(self._owner_group_policy_view,tenant,writer,object,predicate,set_id)

    async def owner_append_group_policy(self,tenant,writer,object,at,fence,predicate,set_id,config):
        self._group_policy_shape(config)
        config=json.loads(encoded(config))
        return await self._work(self.append_group_policy,tenant,writer,object,at,fence,predicate,set_id,config)

    async def owner_mutate(self, tenant, writer, object, at, fence, operation, payload):
        return await self._work(self.mutate, tenant, writer, object, at, fence, operation, payload)

    async def prepare_wrap_write(self, tenant, owner, object, at, fence, metadata, digest, length):
        return await self._work(self.prepare_write,tenant,owner,object,at,fence,metadata,digest,length)

    async def commit_wrap_write(self, permit):
        return await self._work(self.commit_write,permit)
