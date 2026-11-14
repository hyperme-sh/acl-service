"""Protected-source request signing wire adapter, independent of service startup."""
import base64
import json
import re
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .media_allocation_grant import (
    AllocationRejected, AllocationScope, canonical_message, verify_allocation_request, _uuid,
)


class AllocationRequestSigner:
    """Configured adapter for ACL's protected prepare_allocation_request callback."""
    def __init__(self, *, issuer: str, source: str, tenant: str, policy_digest: str,
                 key_id: str, signing_key: Ed25519PrivateKey):
        self.issuer, self.source, self.tenant = _uuid(issuer), _uuid(source), _uuid(tenant)
        if (not re.fullmatch(r'[0-9a-f]{64}', policy_digest)
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', key_id)
                or not isinstance(signing_key, Ed25519PrivateKey)):
            raise AllocationRejected('Invalid source signing configuration')
        self.policy_digest, self.key_id, self.signing_key = policy_digest, key_id, signing_key

    def __call__(self, authorized: dict) -> bytes:
        from .media_allocation_grant import REQUEST_DOMAIN
        if (type(authorized) is not dict or set(authorized) != {'tenant','object','owner','policyDigest',
                'ownershipDigest','issuedAt','expiresAt'} or authorized['tenant'] != self.tenant
                or authorized['policyDigest'] != self.policy_digest):
            raise AllocationRejected('Source signing scope mismatch')
        scope = AllocationScope(self.issuer,self.tenant,authorized['object'],authorized['owner'],
                                self.source,self.policy_digest,authorized['ownershipDigest'])
        claims = {**scope.claims(),'version':1,'allocation':str(uuid4()),
                  'issuedAt':authorized['issuedAt'],'expiresAt':authorized['expiresAt']}
        signature = self.signing_key.sign(canonical_message(self.key_id,claims,domain=REQUEST_DOMAIN))
        raw = json.dumps({'keyId':self.key_id,'claims':claims,
                          'signature':base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')},
                         sort_keys=True,separators=(',',':')).encode('ascii')
        verify_allocation_request(raw,expected=scope,keys={self.key_id:self.signing_key.public_key()},
                                  now=authorized['issuedAt'])
        return raw
