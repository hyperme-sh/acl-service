"""Source-signed permanent media retirement command; no provider activation."""
import base64
from dataclasses import dataclass
import json
import re
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .media_allocation_grant import AllocationRejected, _b64, _integer, _unique, _uuid, canonical_message

DOMAIN = b'spanopticon-media-retirement-v1\x00'
MAX_BYTES = 4096
FIELDS = {'version','issuer','tenant','source','object','owner','command','issuedAt','expiresAt'}


@dataclass(frozen=True)
class RetirementScope:
    issuer: str
    tenant: str
    source: str
    object: str
    owner: str
    command: str

    def claims(self):
        for value in (self.issuer,self.tenant,self.source): _uuid(value)
        if type(self.command) is not str or not re.fullmatch('[0-9a-f]{64}',self.command):
            raise AllocationRejected('Invalid retirement command')
        if type(self.owner) is not str or len(self.owner)!=87 or self.owner.count('.')!=1:
            raise AllocationRejected('Invalid retirement owner')
        x,y=(_b64(part,32) for part in self.owner.split('.'))
        try: ec.EllipticCurvePublicNumbers(int.from_bytes(x),int.from_bytes(y),ec.SECP256R1()).public_key()
        except ValueError as exc: raise AllocationRejected('Invalid retirement owner') from exc
        prefix='media_p_'+(x+y).hex()+'_'
        if type(self.object) is not str or not self.object.startswith(prefix) or not re.fullmatch('[0-9a-f]{32}',self.object[len(prefix):]):
            raise AllocationRejected('Retirement object does not belong to owner')
        return {'issuer':self.issuer,'tenant':self.tenant,'source':self.source,'object':self.object,'owner':self.owner,'command':self.command}


@dataclass(frozen=True)
class VerifiedRetirement:
    scope: RetirementScope
    issued_at: int
    expires_at: int


def verify_retirement_request(raw: bytes, *, expected: RetirementScope,
                              keys: Mapping[str,Ed25519PublicKey], now: int):
    """Only configured source keys authorize this distinct command domain.

    Storage must independently match issuer/tenant/source/owner against the
    permanent allocation row before changing state. This proof cannot allocate
    an object, supply content references, or bypass shared-reference cleanup.
    """
    _integer(now); wanted=expected.claims()
    if type(raw) is not bytes or not 1<=len(raw)<=MAX_BYTES or not 1<=len(keys)<=16:
        raise AllocationRejected('Invalid retirement envelope')
    try: envelope=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique)
    except (UnicodeError,ValueError,RecursionError) as exc:
        raise AllocationRejected('Invalid retirement envelope') from exc
    if type(envelope) is not dict or set(envelope)!={'keyId','claims','signature'}:
        raise AllocationRejected('Invalid retirement envelope')
    key_id,claims=envelope['keyId'],envelope['claims']
    if type(key_id) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}',key_id):
        raise AllocationRejected('Invalid retirement key')
    key=keys.get(key_id)
    if not isinstance(key,Ed25519PublicKey): raise AllocationRejected('Untrusted retirement key')
    if type(claims) is not dict or set(claims)!=FIELDS or type(claims['version']) is not int or claims['version']!=1:
        raise AllocationRejected('Invalid retirement claims')
    if any(type(claims[name]) is not str or claims[name]!=value for name,value in wanted.items()):
        raise AllocationRejected('Retirement scope mismatch')
    issued,expires=_integer(claims['issuedAt']),_integer(claims['expiresAt'])
    if not issued<=now<expires or not 0<expires-issued<=30:
        raise AllocationRejected('Retirement request expired or not current')
    signature=_b64(envelope['signature'],64)
    try: key.verify(signature,canonical_message(key_id,claims,domain=DOMAIN))
    except InvalidSignature as exc: raise AllocationRejected('Invalid retirement signature') from exc
    return VerifiedRetirement(expected,issued,expires)


class RetirementRequestSigner:
    """Called only after checking the durable source tombstone and checkpoint.

    A retry may sign the same permanent command with a fresh short transport
    window. It never recreates owner consent or changes the accepted command.
    """
    def __init__(self, *, issuer,tenant,source,key_id,signing_key):
        self.issuer,self.tenant,self.source=(_uuid(v) for v in (issuer,tenant,source))
        if type(key_id) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}',key_id) or not isinstance(signing_key,Ed25519PrivateKey):
            raise AllocationRejected('Invalid retirement signer')
        self.key_id,self.signing_key=key_id,signing_key

    def sign(self, *, object,owner,command,now):
        _integer(now)
        scope=RetirementScope(self.issuer,self.tenant,self.source,object,owner,command)
        claims={**scope.claims(),'version':1,'issuedAt':now,'expiresAt':now+30}
        _integer(claims['expiresAt'])
        signature=self.signing_key.sign(canonical_message(self.key_id,claims,domain=DOMAIN))
        return json.dumps({'keyId':self.key_id,'claims':claims,'signature':base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')},sort_keys=True,separators=(',',':')).encode('ascii')
