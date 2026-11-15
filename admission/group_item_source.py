"""Joint protected item/group key preparation; this does not grant delivery."""
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
                if claims['grantRevision']>=MAX_SAFE or claims['until']<=at*1000+window:
                    raise AdmissionRejected('direct grant cannot cover next group epoch')
                candidate={**claims,'epoch':epoch,'grantRevision':claims['grantRevision']+1}
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
