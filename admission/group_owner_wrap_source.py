"""Owner-only material for preparing a complete group item repair."""
import hashlib
import hmac
import re
from statement_source import encoded
from acl_service.domain.group_owner_wrap import GroupOwnerWrapPermit
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.authority_checkpoint import authority_digest


class GroupOwnerWrapSource:
    def __init__(self,items):
        self.items,self.media,self.store=items,items.media,items.store

    def _permit(self,db,tenant,owner,object,predicate,set_id,at,expires=None):
        view,row,doc,ids,current=self.items._authority(db,tenant,owner,object,at)
        projection=view['projection']
        if (not projection or not projection.get('snapshot') or
                (projection['predicate'],projection['set'])!=(predicate,set_id) or
                (current is None and projection['snapshot']['objectSet']['stated']!=0)):
            raise AdmissionRejected('current owner maintenance scope required')
        parent,item_digest,commitment,_=self.items._maintenance_parent(db,tenant,owner,object,row,doc,ids,at)
        wrap=doc.get('wraps',{}).get(owner)
        binding=ids['bindings'][owner]
        if (type(wrap) is not dict or (wrap.get('epoch'),wrap.get('revisionId'))!=(parent['epoch'],parent['revisionId']) or
                wrap.get('readerEpub')!=binding.get('epub') or wrap.get('itemDigest')!=item_digest or
                any(type(wrap.get(field)) is not str or re.fullmatch('[a-f0-9]{64}',wrap[field]) is None for field in ('record','digest'))):
            raise AdmissionRejected('matching owner maintenance wrap required')
        claims=self.media._latest(doc)[owner]['claims']
        limit=min(at+2,doc['policyUntil'],claims['until']//1000)
        if current is not None:limit=min(limit,current[0]['policyUntil'])
        expires=limit if expires is None else expires
        if type(expires) is not int or not at<expires<=limit:
            raise AdmissionRejected('owner maintenance permit expired')
        fields=['group-owner-wrap-v1',tenant,owner,object,predicate,set_id,parent,wrap,commitment,
                projection,current,ids,row[0],hashlib.sha256(row[2]).hexdigest(),authority_digest(db).hex(),expires]
        fence=hmac.new(row[1],encoded(fields),hashlib.sha256).hexdigest()
        return GroupOwnerWrapPermit(tenant,owner,object,predicate,set_id,wrap['record'],wrap['digest'],
            parent['epoch'],parent['revisionId'],binding['epub'],commitment,item_digest,fence,expires),ids

    def authorize(self,tenant,owner,object,predicate,set_id,cancel=lambda:None):
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=False,before_commit=guard) as db:
            return self._permit(db,tenant,owner,object,predicate,set_id,at)[0]

    def commit(self,permit,cancel=lambda:None):
        if type(permit) is not GroupOwnerWrapPermit:
            raise AdmissionRejected('invalid owner maintenance permit')
        at=int(self.media.clock());guard=lambda:self.media._guard(at,cancel);guard()
        with self.store._transaction(write=True,before_commit=guard) as db:
            current,ids=self._permit(db,permit.tenant,permit.owner,permit.object,permit.predicate,permit.set_id,at,permit.expires_at)
            if current!=permit:raise HistoryConflict('owner maintenance authority changed')
            for who,binding in ids['bindings'].items():self.store._observe_floor(db,who,binding['head'])
        return True
