"""Object-bound wraps use the durable media registry, never generic records."""
import base64
import copy
import hashlib
import re
from acl_service.infrastructure.private_wrap_store import PrivateWrapStore


class AllocatedWrapStore(PrivateWrapStore):
    _create_statuses=(201,204)

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._payload_base=self._base.removesuffix('/records/media/')+'/media/payloads/'
        self._bound_object=None

    def for_object(self,media_object):
        if type(media_object) is not str:
            raise ValueError('invalid allocated media object')
        match=re.fullmatch(r'media_p_([0-9a-f]{128})_[0-9a-f]{32}',media_object)
        if match is None:raise ValueError('invalid allocated media object')
        point=bytes.fromhex(match[1])
        owner='.'.join(base64.urlsafe_b64encode(part).rstrip(b'=').decode() for part in (point[:32],point[32:]))
        bound=copy.copy(self)
        bound._bound_object=media_object
        bound._base=self._payload_base+media_object+'/wrap/'
        bound._headers={**self._headers,'X-Media-Owner':owner}
        return bound

    def _path(self,name):
        if self._bound_object is None:raise ValueError('media object binding required')
        return super()._path(name)

    async def read(self,name,revision,*,cancel=lambda:None):
        if name!=revision:raise ValueError('allocated wrap digest mismatch')
        return await super().read(name,revision,cancel=cancel)

    async def create(self,name,payload,*,cancel=lambda:None):
        if type(payload) is not bytes or hashlib.sha256(payload).hexdigest()!=name:
            raise ValueError('allocated wrap digest mismatch')
        return await super().create(name,payload,cancel=cancel)
