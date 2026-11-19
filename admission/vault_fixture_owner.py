"""Controller-only enrollment for a declared s3r.ch TEST vault owner."""
import re
from uuid import UUID

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from history_admission import HistoryAdmission


def enroll_test_vault_owner(store, *, manifest, declaration, grant_for, trust_at,
                            genesis, signature, guard, clock):
    """Use controller-owned declarations, grant and witness trust for signed genesis."""
    fields = {'environment', 'network', 'tenant', 'source', 'owner', 'vaultId'}
    if (type(declaration) is not dict or set(declaration) != fields
            or declaration['environment'] != 'test' or declaration['network'] != 's3r.ch'
            or manifest.get('environment') != 'test'):
        raise AdmissionRejected('dedicated TEST vault declaration required')
    tenants = [row for row in manifest.get('tenants', []) if row.get('key') == 's3rch'
               and row.get('network') == 's3r.ch' and row.get('active') is True]
    tenant, source, owner = (declaration[key] for key in ('tenant', 'source', 'owner'))
    vault_id = declaration['vaultId']
    try:
        valid_scope = str(UUID(source)) == source and UUID(source).int != 0
    except (ValueError, TypeError, AttributeError):
        valid_scope = False
    if (len(tenants) != 1 or tenants[0].get('id') != tenant
            or (getattr(store, 'tenant', None), getattr(store, 'source', None)) != (tenant, source)
            or not valid_scope or not isinstance(owner, str)
            or re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}', owner) is None
            or not isinstance(vault_id, str) or re.fullmatch(r'[a-f0-9]{64}', vault_id) is None
            or not callable(guard)):
        raise AdmissionRejected('vault owner or authority scope differs')

    authority = f's3rch-test-vault-v1:{tenant}:{source}:{vault_id}'

    def scoped_grant(principal):
        guard()
        grant = grant_for(principal)
        if grant is None or grant.authority != authority:
            raise AdmissionRejected('dedicated TEST vault grant required')
        return grant

    adapter = HistoryAdmission(store, grant_for=scoped_grant, trust_at=trust_at, clock=clock)
    try:
        adapter.enroll(owner, genesis, signature, before_commit=guard)
    except HistoryConflict:
        guard()
        existing = store.read(owner)
        if existing is None or existing.principal != owner or existing.genesis != genesis:
            raise
        return False
    return True
