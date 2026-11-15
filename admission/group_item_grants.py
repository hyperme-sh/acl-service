"""Owner-signed group item grants, separate from direct media grants."""
import hashlib
import hmac
import json
import re
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict

MAX_SAFE=9007199254740991
CLAIMS={'object','accessor','from','until','stated','epoch','owner','grantRevision','itemCiphertextDigest'}


def grant_key(predicate,set_id,reader):
    return encoded([predicate,set_id,reader]).decode('ascii')


def journal(document):
    return document.get('groupItemGrants',{'rows':[],'frozen':[],'conflicts':[]})


def latest(document,predicate,set_id,reader):
    rows=[row for row in journal(document)['rows'] if (row['predicate'],row['set'],row['claims']['accessor'])==(predicate,set_id,reader)]
    return max(rows,key=lambda row:row['claims']['grantRevision'],default=None)


def reserve(document):
    """Reserve bounded cancellation/fork writes against all other media writes."""
    held=journal(document)
    cancellations=sum(row['claims']['stated']==0 for row in held['rows'])
    pending=(64-cancellations+64-len(held['conflicts']))*5120
    if (cancellations>64 or len(held['conflicts'])>64 or
            len(encoded(held))+pending>1024*1024):raise AdmissionRejected('group item grant capacity')
    return pending


def version_reserve(document):
    held=journal(document);current={}
    for row in held['rows']:
        key=grant_key(row['predicate'],row['set'],row['claims']['accessor'])
        if key not in current or row['claims']['grantRevision']>current[key]['grantRevision']:current[key]=row['claims']
    return sum(1+(claims['stated']==1) for key,claims in current.items() if key not in held['frozen'])


class GroupItemGrants:
    def __init__(self,items):
        self.items,self.media,self.store=items,items.media,items.store

    def _owner(self,db,tenant,owner,object,at,predicate,set_id):
        if tenant!=self.media.tenant:raise AdmissionRejected('wrong group item tenant')
        self.media._group_key(predicate,set_id)
        row,doc=self.media._load(db,object,at)
        ids=self.media.identities(db,object,doc,at)
        if ids['owner']!=owner:raise AdmissionRejected('media owner required')
        return row,doc,ids

    def _draft(self,db,tenant,owner,object,at,predicate,set_id,reader,withdraw):
        row,doc,ids=self._owner(db,tenant,owner,object,at,predicate,set_id)
        key=grant_key(predicate,set_id,reader);held=latest(doc,predicate,set_id,reader)
        if key in journal(doc)['frozen']:raise AdmissionRejected('group item grant fork frozen')
        revision=held['claims']['grantRevision']+1 if held else 1
        if revision>MAX_SAFE:raise AdmissionRejected('group item grant revision exhausted')
        context=self.media._fence(db,object,row,at)
        if withdraw:
            if held is None or held['claims']['stated']!=1:raise AdmissionRejected('no group item grant to cancel')
            claims={**held['claims'],'stated':0,'grantRevision':revision}
        else:
            view,_,_,_,current=self.items._authority(db,tenant,owner,object,at)
            projection=view['projection']
            if current is None or (projection['predicate'],projection['set'])!=(predicate,set_id):
                raise AdmissionRejected('current item group binding required')
            group,snapshot,config=current
            if (reader not in ids['bindings'] or len([m for m in snapshot['members']
                    if m['accessor']==reader and m['stated']==1])!=1):raise AdmissionRejected('current group recipient required')
            item,_,_,current_doc=self.media._permit(db,tenant,owner,object,at)
            if item.epoch>=MAX_SAFE:raise AdmissionRejected('item epoch exhausted')
            until=min(doc['policyUntil'],group['policyUntil'])*1000
            if until<=at*1000+config['settleWindowMs']:raise AdmissionRejected('group item policy cannot settle')
            claims={'object':object,'accessor':reader,'from':at*1000,'until':until,'stated':1,
                'epoch':item.epoch+1,'owner':owner,'grantRevision':revision,
                'itemCiphertextDigest':current_doc['wraps'][owner]['itemDigest']}
            context=[view['fence'],item.fence]
        fields=['group-item-grant-v1',tenant,owner,object,predicate,set_id,reader,withdraw,at,context]
        fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
        return {'at':at,'fence':fence,'ownerPub':ids['bindings'][owner]['pub'],'grant':claims},row,doc,ids

    def view(self,tenant,owner,object,predicate,set_id,reader,withdraw=False,cancel=lambda:None):
        if type(reader) is not str or not 1<=len(reader)<=1024 or type(withdraw) is not bool:raise AdmissionRejected('invalid group grant target')
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            return self._draft(db,tenant,owner,object,at,predicate,set_id,reader,withdraw)[0]

    def append(self,tenant,owner,object,predicate,set_id,at,fence,payload,cancel=lambda:None):
        guard=lambda:self.media._guard(at,cancel);guard()
        if type(payload) is not dict or set(payload)!={'claims','proof'} or len(encoded(payload))>4096:
            raise AdmissionRejected('invalid group item grant')
        payload=json.loads(encoded(payload));claims=payload['claims']
        if (type(claims) is not dict or set(claims)!=CLAIMS or claims['object']!=object or claims['owner']!=owner or
                type(claims['accessor']) is not str or not 1<=len(claims['accessor'])<=1024 or
                any(type(claims[k]) is not int or not 0<=claims[k]<=MAX_SAFE for k in ('from','until','stated','epoch','grantRevision')) or
                claims['stated'] not in (0,1) or claims['until']<=claims['from'] or claims['epoch']<1 or claims['grantRevision']<1 or
                type(claims['itemCiphertextDigest']) is not str or re.fullmatch('[a-f0-9]{64}',claims['itemCiphertextDigest']) is None):
            raise AdmissionRejected('invalid group item grant claims')
        frozen=False
        with self.store._transaction(write=True,before_commit=guard) as db:
            row,doc,ids=self._owner(db,tenant,owner,object,at,predicate,set_id)
            owner_pub=ids['bindings'][owner]['pub']
            if not self.media.native[0].matches_grant(encoded(payload['proof']),encoded({**claims,'ownerPub':owner_pub})):
                raise AdmissionRejected('group item grant signature refused')
            key=grant_key(predicate,set_id,claims['accessor']);held=journal(doc)
            if key in held['frozen']:raise AdmissionRejected('group item grant fork frozen')
            retained=next((r for r in held['rows'] if (r['predicate'],r['set'],r['claims']['accessor'],r['claims']['grantRevision'])==
                (predicate,set_id,claims['accessor'],claims['grantRevision'])),None)
            if retained and encoded(retained['claims'])==encoded(claims):return True
            record={'predicate':predicate,'set':set_id,**payload,'ownerPub':owner_pub}
            if len(encoded(record))>5120:raise AdmissionRejected('group item grant record capacity')
            if retained:
                held['frozen'].append(key);held['conflicts'].append(record);frozen=True
            else:
                view,_,_,_=self._draft(db,tenant,owner,object,at,predicate,set_id,claims['accessor'],claims['stated']==0)
                if type(fence) is not str or not hmac.compare_digest(fence,view['fence']) or encoded(claims)!=encoded(view['grant']):
                    raise HistoryConflict('group item grant authority changed')
                if sum(r['claims']['stated']==claims['stated'] for r in held['rows'])>=64:raise AdmissionRejected('group item grant capacity')
                held['rows'].append(record)
            if doc['objectVersion']>=MAX_SAFE:raise AdmissionRejected('object version exhausted')
            doc['groupItemGrants']=held;doc['objectVersion']+=1
            doc['groupWithdrawalCapacity']=True
            reserve(doc)
            self.media._save(db,object,row,doc)
        if frozen:raise AdmissionRejected('group item grant fork frozen')
        return True
