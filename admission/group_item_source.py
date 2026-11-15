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
