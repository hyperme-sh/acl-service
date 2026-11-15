"""Protected group item preparation, admission and current read authority."""
import hashlib
import hmac
import json
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected


class GroupItemSource:
    def __init__(self, keys):
        self.keys,self.media,self.store=keys,keys.media,keys.store

    def authority_view(self,tenant,owner,object,cancel=lambda:None):
        """Join retained item edges with current independent membership, read-only."""
        at=int(self.media.clock())
        guard=lambda:self.media._guard(at,cancel)
        guard()
        if tenant!=self.media.tenant:
            raise AdmissionRejected('wrong group item tenant')
        with self.store._transaction(write=False,before_commit=guard) as db:
            return self._authority(db,tenant,owner,object,at)[0]

    def _authority(self,db,tenant,owner,object,at):
        row,document=self.media._load(db,object,at)
        identities=self.media.identities(db,object,document,at)
        if identities['owner']!=owner:
            raise AdmissionRejected('media owner required')
        scopes=document.get('groupScopes',{})
        if type(scopes) is not dict or len(scopes)>8:
            raise AdmissionRejected('group item scope capacity')
        projected=json.loads(encoded(document))
        projected['groupScopes']={}
        group_fences=[]
        current=None
        for key,retained in sorted(scopes.items()):
            # A media row may retain old membership rows for compatibility.
            # They must never substitute for the independent current journal.
            edges=[entry for entry in retained if entry['kind']!='membership' and not (
                entry['kind']=='cancel' and entry['record']['kind']=='membership')]
            projected['groupScopes'][key]=edges
        projection=self.media._group_object_projection(db,object,projected,at)
        # Resolve only owner-signed item edges first. Owning an item is not
        # authority to enumerate arbitrary groups named in its old edges.
        if projection and projection['snapshot'] is not None and projection['snapshot']['objectSet']['stated']==1:
            predicate,set_id=projection['predicate'],projection['set']
            held,group,snapshot,config=self.keys._load_current(db,tenant,at,predicate,set_id)
            members=[member for member in snapshot['members']
                     if member['accessor']==owner and member['stated']==1]
            if len(members)!=1:
                raise AdmissionRejected('current explicit group membership required')
            key=self.media._group_key(predicate,set_id)
            projected['groupScopes'][key]+=group['rows']
            projection=self.media._group_object_projection(db,object,projected,at)
            group_fences.append(self.keys._fence(db,held,at,predicate,set_id))
            current=(group,snapshot,config)
        fields=['group-item-authority-v1',tenant,owner,object,at,
                self.media._fence(db,object,row,at),group_fences]
        fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
        result={'at':at,'fence':fence,'projection':projection,
                'objectVersion':document['objectVersion'],
                'ownerPub':identities['bindings'][owner]['pub']}
        return result,row,document,identities,current

    def view(self,tenant,owner,object,predicate,set_id,cancel=lambda:None):
        at=int(self.media.clock())
        guard=lambda:self.media._guard(at,cancel)
        guard()
        if tenant!=self.media.tenant:
            raise AdmissionRejected('wrong group item tenant')
        with self.store._transaction(write=False,before_commit=guard) as db:
            # Both selectors verify current native authority, identity, settlement,
            # retained checkpoints and expiry under this same protected source lock.
            item,identities,row,document=self.media._permit(db,tenant,owner,object,at)
            if identities['owner']!=owner:
                raise AdmissionRejected('media owner required')
            group=self.keys._read_permit(db,tenant,owner,at,predicate,set_id)
            if (item.tenant,item.reader,item.object)!=(tenant,owner,object) or (
                    group.tenant,group.reader,group.predicate,group.set_id)!=(tenant,owner,predicate,set_id):
                raise AdmissionRejected('group item scope changed')
            expires=min(item.expires_at,group.expires_at)
            if not at<expires<=at+2:
                raise AdmissionRejected('group item preparation expired')
            item_digest=document['wraps'][owner]['itemDigest']
            fields=['group-item-view-v1',tenant,owner,object,predicate,set_id,at,
                    item.fence,group.fence,expires]
            fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
            return {'at':at,'expiresAt':expires,'fence':fence,
                    'object':object,'predicate':predicate,'set':set_id,
                    'ownerPub':identities['bindings'][owner]['pub'],
                    'item':{'epoch':item.epoch,'revisionId':item.revision_id,'digest':item_digest},
                    'group':{'epoch':group.epoch,'revisionId':group.revision_id,
                             'keyCommitment':group.key_commitment}}

    def _epoch_plan(self,db,tenant,owner,object,at,predicate,set_id):
        """Prepare the complete next item snapshot without changing either grant journal."""
        from group_item_grants import journal, latest, grant_key, MAX_SAFE
        view,row,doc,ids,current=self._authority(db,tenant,owner,object,at)
        if current is None or (view['projection']['predicate'],view['projection']['set'])!=(predicate,set_id):
            raise AdmissionRejected('current item group binding required')
        group,cohort,config=current
        item,_,_,_=self.media._permit(db,tenant,owner,object,at)
        parent=self.media._selected_finalization(object,doc,at,historical=True)
        if parent['epoch']!=item.epoch or not 1<=item.epoch<MAX_SAFE:
            raise AdmissionRejected('current item epoch required')
        epoch=item.epoch+1;window=config['settleWindowMs'];owner_pub=ids['bindings'][owner]['pub']
        if min(doc['policyUntil'],group['policyUntil'])*1000<=at*1000+window:
            raise AdmissionRejected('group item policy cannot cover settlement')
        item_digest=doc['wraps'][owner]['itemDigest']
        direct=self.media._latest(doc);drafts=[];entries={};bindings={}
        # Refresh independently authorized direct recipients into the new item
        # epoch. Membership never creates a direct grant or extends its window.
        for who,held in sorted(direct.items()):
            claims=held['claims'];candidate=claims
            if claims['stated']==1 and claims['until']<=at*1000:
                if claims['grantRevision']>=MAX_SAFE:raise AdmissionRejected('direct grant revision exhausted')
                candidate={**claims,'epoch':epoch,'grantRevision':claims['grantRevision']+1,'stated':0}
                drafts.append(candidate)
            elif claims['stated']==1:
                if (who in doc['frozen'] or who not in ids['bindings'] or claims['from']>at*1000 or
                        claims['itemCiphertextDigest']!=item_digest or claims['owner']!=owner or
                        not self.media.native[0].matches_grant(encoded(held['proof']),encoded({**claims,'ownerPub':owner_pub}))):
                    raise AdmissionRejected('current direct recipient required')
                until=min(claims['until'],doc['policyUntil']*1000)
                if claims['grantRevision']>=MAX_SAFE or until<=at*1000+window:
                    raise AdmissionRejected('direct grant cannot cover next group epoch')
                candidate={**claims,'epoch':epoch,'grantRevision':claims['grantRevision']+1,'until':until}
                drafts.append(candidate);bindings[who]=ids['bindings'][who]
            entries[who]={'accessor':who,'grantRevision':candidate['grantRevision'],
                'stated':candidate['stated'],'from':candidate['from'],'until':candidate['until'],
                'scope':'direct','setId':'','hamState':0}
        projection=view['projection'];edge=projection['snapshot']['objectSet']
        members={member['accessor']:member for member in projection['snapshot']['members']}
        granted={entry['claims']['accessor'] for entry in journal(doc)['rows']
                 if (entry['predicate'],entry['set'])==(predicate,set_id)}
        group_readers=[]
        for who in sorted(granted):
            held=latest(doc,predicate,set_id,who);claims=held['claims'];member=members.get(who)
            live=(claims['stated']==1 and claims['from']<=at*1000<claims['until'] and
                  member is not None and member['stated']==1 and who in projection['members'] and
                  grant_key(predicate,set_id,who) not in journal(doc)['frozen'])
            prior=entries.get(who)
            if prior and ((prior['stated']==1 and prior['from']<=at*1000<prior['until']) or not live):
                continue
            if live:
                if (who not in ids['bindings'] or claims['epoch']!=epoch or claims['itemCiphertextDigest']!=item_digest or
                        claims['until']<=at*1000+window or claims['until']>min(doc['policyUntil'],group['policyUntil'])*1000 or
                        claims['owner']!=owner or not self.media.native[0].matches_grant(
                            encoded(held['proof']),encoded({**claims,'ownerPub':owner_pub}))):
                    raise AdmissionRejected('current group item grant required')
            # The native snapshot has one row per accessor. An independently
            # live direct grant is selected first; otherwise a live group grant
            # may authorize that accessor. Both histories remain untouched.
            entries[who]={'accessor':who,'grantRevision':claims['grantRevision'],
                'stated':1 if live else 0,'from':claims['from'],'until':claims['until'],
                'scope':predicate,'setId':set_id,'hamState':member['hamState'] if member else 0}
            if live:group_readers.append(who)
        if (owner not in bindings or len(entries)>64 or len(doc['manifests'])>=64 or len(doc['finalizations'])>=64 or
                any(sum(entry['claims']['stated']==stated for entry in doc['grants'])+
                    sum(draft['stated']==stated for draft in drafts)>64 for stated in (0,1))):
            raise AdmissionRejected('group item epoch capacity')
        snapshot={'entries':[entries[who] for who in sorted(entries)],'objectSet':edge}
        fields=['group-item-epoch-plan-v1',tenant,owner,object,at,predicate,set_id,view['fence'],item.fence,
                parent['finalizationId'],snapshot,drafts,window]
        fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
        return {'at':at,'fence':fence,'owner':owner,'ownerPub':owner_pub,'predicate':predicate,'set':set_id,
                'previousEpoch':parent['epoch'],'previousFinalizationId':parent['finalizationId'],
                'settleWindowMs':window,'grants':drafts,'snapshot':snapshot,'bindings':bindings,
                'groupReaders':group_readers}

    def epoch_view(self,tenant,owner,object,predicate,set_id,cancel=lambda:None):
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel)
        guard()
        if tenant!=self.media.tenant:raise AdmissionRejected('wrong group item tenant')
        self.media._group_key(predicate,set_id)
        with self.store._transaction(write=False,before_commit=guard) as db:
            return json.loads(encoded(self._epoch_plan(db,tenant,owner,object,at,predicate,set_id)))

    @staticmethod
    def _epoch_command(payload,object,owner):
        from group_item_grants import parse_payload
        if (type(payload) is not dict or set(payload)!={'grants','document','finalization'} or
                len(encoded(payload))>262144 or type(payload['grants']) is not list or
                not 1<=len(payload['grants'])<=64 or type(payload['document']) is not dict or
                type(payload['finalization']) is not dict):
            raise AdmissionRejected('invalid group item epoch command')
        payload=json.loads(encoded(payload))
        for grant in payload['grants']:parse_payload(grant,object,owner)
        return payload

    def _epoch_command_state(self,db,tenant,owner,object,at,predicate,set_id,payload):
        from group_item_grants import GroupItemGrants
        row,doc,ids=GroupItemGrants(self)._owner(db,tenant,owner,object,at,predicate,set_id)
        digest=hashlib.sha256(encoded(['group-item-epoch-command-v1',tenant,owner,object,predicate,set_id,payload])).hexdigest()
        retained=any(entry['command']==digest for entry in doc.get('groupItemEpochs',[]))
        return retained,digest,row,doc,ids

    def epoch_state(self,tenant,owner,object,predicate,set_id,payload,cancel=lambda:None):
        """Confirm exact retained bytes, not settlement or present access."""
        payload=self._epoch_command(payload,object,owner)
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            retained,_,_,_,_=self._epoch_command_state(db,tenant,owner,object,at,predicate,set_id,payload)
            return {'at':at,'state':'applied' if retained else 'absent'}

    def append_epoch(self,tenant,owner,object,predicate,set_id,at,fence,payload,cancel=lambda:None):
        """Internal atomic admission; no HTTP installation or delivery activation."""
        from acl_service.domain.history_store import HistoryConflict
        from group_item_grants import MAX_SAFE
        payload=self._epoch_command(payload,object,owner)
        guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            retained,digest,row,doc,ids=self._epoch_command_state(db,tenant,owner,object,at,predicate,set_id,payload)
            if retained:return True
            plan=self._epoch_plan(db,tenant,owner,object,at,predicate,set_id)
            if type(fence) is not str or not hmac.compare_digest(fence,plan['fence']):
                raise HistoryConflict('group item epoch authority changed')
            if encoded([grant['claims'] for grant in payload['grants']])!=encoded(plan['grants']):
                raise HistoryConflict('group item epoch recipients changed')
            owner_pub=ids['bindings'][owner]['pub']
            for grant in payload['grants']:
                if not self.media.native[0].matches_grant(encoded(grant['proof']),encoded({**grant['claims'],'ownerPub':owner_pub})):
                    raise AdmissionRejected('group item direct grant signature refused')
            document=payload['document'];fin=payload['finalization'];manifest=document.get('manifest')
            if type(manifest) is not dict:raise AdmissionRejected('invalid group item manifest')
            expected={'ownerPub':owner_pub,'object':object,'epoch':plan['previousEpoch']+1,'revisionId':manifest.get('revisionId')}
            if (document.get('snapshot')!=plan['snapshot'] or manifest.get('previousEpoch')!=plan['previousEpoch'] or
                    manifest.get('settleWindowMs')!=plan['settleWindowMs'] or
                    manifest.get('keyCommitment')!=self.media._selected(object,doc,at)['keyCommitment'] or
                    not self.media.native[2].matches_manifest(encoded(document),encoded(expected))):
                raise AdmissionRejected('group item manifest refused')
            if (fin.get('previousEpoch')!=plan['previousEpoch'] or fin.get('previousFinalizationId')!=plan['previousFinalizationId'] or
                    fin.get('epoch')!=expected['epoch'] or fin.get('revisionId')!=expected['revisionId'] or
                    fin.get('candidateRevisionIds')!=[expected['revisionId']] or
                    any(entry['proof']['finalizationId']==fin.get('finalizationId') for entry in doc['finalizations'])):
                raise HistoryConflict('group item ancestry changed')
            if len(doc.get('groupItemEpochs',[]))>=64 or doc['objectVersion']>=MAX_SAFE:
                raise AdmissionRejected('group item epoch capacity')
            doc['grants'] += [{**grant,'ownerPub':owner_pub} for grant in payload['grants']]
            doc['manifests'].append({'document':document,'expected':expected})
            doc['finalizations'].append({'proof':fin,'ownerPub':owner_pub,'seenAt':at*1000})
            history=self.media._history(object,doc,at,fin)
            history['current']=plan['snapshot'];history['groupWindowMs']=plan['settleWindowMs']
            if not self.media.native[4].verifies_history(encoded(history)):
                raise AdmissionRejected('group item epoch history refused')
            doc.setdefault('groupItemEpochs',[]).append({'command':digest,'predicate':predicate,'set':set_id,
                'epoch':expected['epoch'],'revisionId':expected['revisionId'],'settleWindowMs':plan['settleWindowMs']})
            doc['objectVersion']+=1
            self.media._save(db,object,row,doc)
        return True

    def _read_snapshot(self,doc,ids,projection,at):
        from group_item_grants import journal,latest,grant_key
        predicate,set_id=projection['predicate'],projection['set']
        entries={entry['accessor']:entry for entry in self.media._snapshot(doc)['entries']}
        members={member['accessor']:member for member in projection['snapshot']['members']}
        readers={row['claims']['accessor'] for row in journal(doc)['rows'] if (row['predicate'],row['set'])==(predicate,set_id)}
        owner=ids['owner'];owner_pub=ids['bindings'][owner]['pub']
        for who in sorted(readers):
            held=latest(doc,predicate,set_id,who);claims=held['claims'];member=members.get(who)
            live=(claims['stated']==1 and claims['from']<=at*1000<claims['until'] and member is not None and
                member['stated']==1 and who in projection['members'] and grant_key(predicate,set_id,who) not in journal(doc)['frozen'])
            prior=entries.get(who)
            if prior and ((prior['stated']==1 and prior['from']<=at*1000<prior['until']) or not live):continue
            if live and (who not in ids['bindings'] or claims['owner']!=owner or
                    not self.media.native[0].matches_grant(encoded(held['proof']),encoded({**claims,'ownerPub':owner_pub}))):
                raise AdmissionRejected('current group item grant required')
            entries[who]={'accessor':who,'grantRevision':claims['grantRevision'],'stated':1 if live else 0,
                'from':claims['from'],'until':claims['until'],'scope':predicate,'setId':set_id,
                'hamState':member['hamState'] if member else 0}
        if len(entries)>64:raise AdmissionRejected('group item snapshot capacity')
        return {'entries':[entries[who] for who in sorted(entries)],'objectSet':projection['snapshot']['objectSet']}

    def _read_permit(self,db,tenant,reader,object,predicate,set_id,at,expires=None,key_expires=None):
        from group_item_grants import journal,latest,grant_key
        from acl_service.domain.group_item_delivery import GroupItemReadPermit
        from acl_service.infrastructure.authority_checkpoint import authority_digest
        import re
        if tenant!=self.media.tenant:raise AdmissionRejected('wrong group item tenant')
        _,doc=self.media._load(db,object,at);ids=self.media.identities(db,object,doc,at)
        view,row,doc,ids,current=self._authority(db,tenant,ids['owner'],object,at)
        projection=view['projection']
        if current is None or (projection['predicate'],projection['set'])!=(predicate,set_id):
            raise AdmissionRejected('current item group binding required')
        key=self.keys._read_permit(db,tenant,reader,at,predicate,set_id,key_expires)
        group,_,config=current
        held=latest(doc,predicate,set_id,reader)
        if held is None or grant_key(predicate,set_id,reader) in journal(doc)['frozen'] or reader not in ids['bindings']:
            raise AdmissionRejected('group item grant unavailable')
        claims=held['claims'];owner=ids['owner'];owner_pub=ids['bindings'][owner]['pub']
        if (claims['owner']!=owner or claims['stated']!=1 or not claims['from']<=at*1000<claims['until'] or
                not self.media.native[0].matches_grant(encoded(held['proof']),encoded({**claims,'ownerPub':owner_pub}))):
            raise AdmissionRejected('group item grant inactive')
        snapshot=self._read_snapshot(doc,ids,projection,at)
        entry=next((entry for entry in snapshot['entries'] if entry['accessor']==reader),None)
        if not entry or entry['scope']!=predicate or entry['setId']!=set_id or entry['stated']!=1:
            raise AdmissionRejected('current group recipient required')
        selected=None
        for finalization in reversed(doc['finalizations']):
            fin=finalization['proof']
            if not any((record['predicate'],record['set'],record['epoch'],record['revisionId'])==
                    (predicate,set_id,fin['epoch'],fin['revisionId']) for record in doc.get('groupItemEpochs',[])):continue
            history=self.media._history(object,doc,at,fin)
            history['current']=snapshot;history['groupWindowMs']=config['settleWindowMs']
            if self.media.native[3].matches_settled(encoded(history)):
                selected=next(record['document']['manifest'] for record in doc['manifests']
                    if record['document']['manifest']['revisionId']==fin['revisionId'])
                break
        if selected is None or claims['epoch']!=selected['epoch']:
            raise AdmissionRejected('current settled group item epoch required')
        status=doc.get('groupItemStatuses',{}).get(grant_key(predicate,set_id,reader))
        expected={'ownerPub':owner_pub,'object':object,'epoch':selected['epoch'],'revisionId':selected['revisionId'],
            'accessor':reader,'grantRevision':claims['grantRevision'],'stated':1,
            'zookie':{'object':object,'objectVersion':doc['objectVersion'],'snapshotHash':selected['aclSnapshot']}}
        if not status or not self.media.native[1].matches_status(encoded(status),encoded(expected),
                now_ms=at*1000,skew_ms=0,policy_max_age_ms=60000):
            raise AdmissionRejected('current group item status required')
        metadata=doc.get('groupItemWraps',{}).get(encoded([predicate,set_id]).decode('ascii'))
        if (type(metadata) is not dict or set(metadata)!={'digest','length','itemEpoch','itemRevisionId','itemDigest','groupEpoch','groupRevisionId','groupKeyCommitment'} or
                type(metadata['length']) is not int or not 1<=metadata['length']<=65536 or
                any(type(metadata[field]) is not int or not 1<=metadata[field]<=9007199254740991 for field in ('itemEpoch','groupEpoch')) or
                any(type(metadata[field]) is not str or re.fullmatch('[a-f0-9]{64}',metadata[field]) is None
                    for field in ('digest','itemRevisionId','itemDigest','groupRevisionId','groupKeyCommitment')) or
                (metadata['itemEpoch'],metadata['itemRevisionId'],metadata['itemDigest'])!=(selected['epoch'],selected['revisionId'],claims['itemCiphertextDigest']) or
                (metadata['groupEpoch'],metadata['groupRevisionId'],metadata['groupKeyCommitment'])!=(key.epoch,key.revision_id,key.key_commitment)):
            raise AdmissionRejected('current group item wrap required')
        limit=min(at+2,doc['policyUntil'],group['policyUntil'],key.expires_at,claims['until']//1000,
            (status['signedAt']+min(status['maxAgeMs'],60000))//1000)
        expires=limit if expires is None else expires
        if type(expires) is not int or not at<expires<=limit:raise AdmissionRejected('group item permit expired')
        fields=['group-item-read-v1',tenant,reader,object,predicate,set_id,metadata,expires,key.fence,
            row[0],hashlib.sha256(row[2]).hexdigest(),authority_digest(db).hex()]
        fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
        return GroupItemReadPermit(key,object,selected['epoch'],selected['revisionId'],claims['itemCiphertextDigest'],
            metadata['digest'],metadata['length'],fence,expires),ids,row,doc

    def authorize_read(self,tenant,reader,object,predicate,set_id,cancel=lambda:None):
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            return self._read_permit(db,tenant,reader,object,predicate,set_id,at)[0]

    def commit_read(self,permit,cancel=lambda:None):
        from acl_service.domain.group_item_delivery import GroupItemReadPermit
        from acl_service.domain.group_wrap import GroupKeyReadPermit
        from acl_service.domain.history_store import HistoryConflict
        if type(permit) is not GroupItemReadPermit or type(permit.key) is not GroupKeyReadPermit:
            raise AdmissionRejected('invalid group item permit')
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        key=permit.key
        with self.store._transaction(write=True,before_commit=guard) as db:
            current,ids,row,doc=self._read_permit(db,key.tenant,key.reader,permit.object,key.predicate,key.set_id,
                at,permit.expires_at,key.expires_at)
            if current!=permit:raise HistoryConflict('group item authority changed')
            for who,binding in ids['bindings'].items():self.store._observe_floor(db,who,binding['head'])
            if permit.item_epoch>doc['floor']:
                doc['floor']=permit.item_epoch;self.media._save(db,permit.object,row,doc)
        return True
