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
from acl_service.infrastructure.epoch_verifier import (
    PrivateGrantVerifier, EpochStatusVerifier, EpochManifestVerifier,
    SettledEpochVerifier, EpochHistoryVerifier,
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
        with store._transaction(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS statement_tenant (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO statement_tenant VALUES(1,?)',(tenant,))
            if db.execute('SELECT tenant FROM statement_tenant WHERE id=1').fetchone()!=(tenant,):
                raise AdmissionRejected('database belongs to another tenant')
            db.execute('CREATE TABLE IF NOT EXISTS media_sources (object TEXT PRIMARY KEY, revision INTEGER NOT NULL, nonce BLOB NOT NULL, document BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS freshness.media_checkpoints (object TEXT PRIMARY KEY, digest BLOB NOT NULL)')

    _guard=StatementSource._guard
    _accounts=StatementSource._accounts
    _digest=staticmethod(StatementSource._digest)
    _fence=StatementSource._fence

    def _identities(self, db, object, doc, at):
        accounts = self._accounts(db)
        principal = next(iter(accounts)); account = accounts[principal]
        runner = HistoryAdmission(self.store, grant_for=lambda _:None,
                                  trust_at=lambda _:doc['policy'], clock=self.clock)
        return json.loads(runner._run_verifier(principal, at, mediaObject=object,
            genesis=_record(account.genesis), entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal, accounts)))

    def _checkpoint(self, db, object, row, *, write=False):
        digest = hashlib.sha256(encoded(['private-media-v1',self.tenant,object])+self._digest(*row)).digest()
        if write:
            db.execute('INSERT INTO freshness.media_checkpoints VALUES(?,?) ON CONFLICT(object) DO UPDATE SET digest=excluded.digest',(object,digest))
        elif db.execute('SELECT digest FROM freshness.media_checkpoints WHERE object=?',(object,)).fetchone() != (digest,):
            raise AdmissionRejected('media checkpoint mismatch')

    def _load(self, db, object, at):
        row = db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
        if row is None: raise AdmissionRejected('media source unavailable')
        self._checkpoint(db,object,row)
        doc = json.loads(row[2])
        if at >= doc['policyUntil']: raise AdmissionRejected('media policy expired')
        return row,doc

    def _save(self, db, object, row, doc):
        raw=encoded(doc)
        if len(raw)>6*1024*1024: raise AdmissionRejected('media capacity')
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
            if db.execute('SELECT COUNT(*) FROM media_sources').fetchone()[0]>=64:
                raise AdmissionRejected('media object capacity')
            if db.execute('SELECT 1 FROM media_sources WHERE object=?',(object,)).fetchone() or db.execute('SELECT 1 FROM freshness.media_checkpoints WHERE object=?',(object,)).fetchone():
                raise HistoryConflict('media object already provisioned')
            self.identities(db,object,doc,at)
            row=(0,secrets.token_bytes(32),encoded(doc))
            if len(row[2])>65536: raise AdmissionRejected('media policy capacity')
            db.execute('INSERT INTO media_sources VALUES(?,?,?,?)',(object,*row))
            self._checkpoint(db,object,row,write=True)

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
            doc.update(policy=policy,policyUntil=policy_until)
            self.identities(db,object,doc,at)
            doc['objectVersion']+=1
            self._save(db,object,row,doc)

    def _selected(self, object, doc, at):
        for row in reversed(doc['finalizations']):
            fin=row['proof']
            if self.native[3].matches_settled(encoded(self._history(object,doc,at,fin))):
                return next(r['document']['manifest'] for r in doc['manifests'] if r['document']['manifest']['revisionId']==fin['revisionId'])
        raise AdmissionRejected('no current settled epoch')

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

    async def owner_view(self, tenant, writer, object):
        return await self._work(self._owner_view, tenant, writer, object)

    def _owner_catalog(self, tenant, writer, page, cancel):
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
            # not affect page positions or nextPage.
            rows = db.execute('SELECT object FROM media_sources WHERE substr(object,1,?)=? ORDER BY object LIMIT 4 OFFSET ?',
                              (len(prefix),prefix,page*4)).fetchall()
            for (object,) in rows:
                self._guard(at,cancel)
                _,doc = self._load(db,object,at)
                identities = self.identities(db,object,doc,at)
                if identities['owner'] == writer:
                    objects.append(object)
            self._guard(at,cancel)
        return {'at':at,'objects':objects,'nextPage':page+1 if page<15 else None}

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

    async def owner_mutate(self, tenant, writer, object, at, fence, operation, payload):
        return await self._work(self.mutate, tenant, writer, object, at, fence, operation, payload)

    async def prepare_wrap_write(self, tenant, owner, object, at, fence, metadata, digest, length):
        return await self._work(self.prepare_write,tenant,owner,object,at,fence,metadata,digest,length)

    async def commit_wrap_write(self, permit):
        return await self._work(self.commit_write,permit)
