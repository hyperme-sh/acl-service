"""Joint protected item/group key preparation; this does not grant delivery."""
import hashlib
import hmac
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected


class GroupItemSource:
    def __init__(self, keys):
        self.keys,self.media,self.store=keys,keys.media,keys.store

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
