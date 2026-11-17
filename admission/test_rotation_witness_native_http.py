"""CI-only native rotation signing with owned PostgreSQL and a public fixture key.

ASGI authentication is substituted; source policy, key parsing, witness locking,
signatures, native verification and database state are exercised together.
"""
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID,uuid4
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from auth_service.schemas import AuthMeResponse
from acl_service import deps
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source
from acl_service.infrastructure.rotation_witness_bindings import load_rotation_bindings
from acl_service.infrastructure.witness_policy_repo import PostgresWitnessSigningPolicyReader,PostgresWitnessPolicyWriter
from acl_service.infrastructure.witness_signer import WitnessKey
from acl_service.interfaces.api.rotation_witness_routes import router
from history_admission import HistoryAdmission,EnrollmentGrant
from rotation_witness_source import RotationWitnessSource
from test_keyring_state_repo import state_url,state_engine  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation',[None,'revoke','offline-current-key-revoke'])
async def test_native_wallet_attestation_and_present_revocation(tmp_path,state_engine,state_url,revocation):
    f=json.loads((Path(__file__).parent/'fixture.json').read_bytes())
    request=copy.deepcopy(f['rotate-v4-wallet']);request.pop('attest')
    principal,now=f['genesis'],request['issuedAt']
    trust={key:f[key] for key in ('jwks','policy','pinnedIss')}
    spec=dict(history_schema='acl_h_'+uuid4().hex,checkpoint_schema='acl_c_'+uuid4().hex,
              tenant=str(uuid4()),source=str(uuid4()))
    provision_empty_media_source(state_url,**spec)
    store=PostgresHistoryStore(state_url,**spec)
    grant=EnrollmentGrant(principal,'qualification','one-use-grant',f['now']+60)
    writer=HistoryAdmission(store,grant_for=lambda _:grant,trust_at=lambda _:trust,clock=lambda:now)
    writer.enroll(principal,json.dumps(f['binding']).encode(),f['signature'])
    writer.admit(principal,json.dumps(f['wallet']).encode())
    if revocation:
        # A signed offline revoke has no timestamp token; install the shared
        # vector in this isolated source so current native checks must reject it.
        snapshot=store.read(principal)
        store.append(principal,len(snapshot.entries),json.dumps(f[revocation]).encode())
    key=ec.derive_private_key(5,ec.SECP256R1())  # Public SociACL vector scalar.
    jwk=f['jwks']['keys'][0]
    with state_engine.begin() as db:db.execute(text('TRUNCATE sociacl_witness_policy'))
    PostgresWitnessPolicyWriter(state_engine).install_verified(1,[WitnessKey(jwk['kid'],jwk['notBefore'],jwk['notAfter'],key.public_key())],check_authorization=lambda:None)
    policy=dict(version=1,**{'from':now-1},until=now+60,trust=trust,activePrincipals=[principal])
    def private(name,value):
        path=tmp_path/name;path.write_bytes(value if isinstance(value,bytes) else json.dumps(value).encode());path.chmod(0o600);return str(path)
    key_path=private('key.pem',key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    policy_path=private('policy.json',policy)
    settings_path=private('source.json',dict(version=1,databaseUrl=state_url,historySchema=spec['history_schema'],checkpointSchema=spec['checkpoint_schema'],tenant=spec['tenant'],source=spec['source']))
    config=private('bindings.json',dict(version=1,bindings=[dict(tenant=spec['tenant'],subject='owner',principal=principal,postgresFile=settings_path,policyFile=policy_path,kid=jwk['kid'],signingKeyFile=key_path)]))
    def source(settings,policy_at,witness,kid,private_key):
        return RotationWitnessSource(settings.open(),policy_at=policy_at,witness_policy=witness,kid=kid,private_key=private_key,clock=lambda:now)
    bindings=load_rotation_bindings(PostgresWitnessSigningPolicyReader(state_engine),{'SOCIACL_ROTATION_BINDINGS_FILE':config},source_factory=source)
    app=FastAPI();app.include_router(router)
    tenant=UUID(spec['tenant']);actor=AuthMeResponse(sub='owner',tenant_id=tenant,scopes=['acl:identity:rotate'])
    app.dependency_overrides[deps.get_current_user]=lambda:actor
    app.dependency_overrides[deps.get_current_tenant_from_token]=lambda:actor.tenant_id
    app.state.rotation_witness_bindings=bindings;app.state.rotation_witness_slots=asyncio.Semaphore(1)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *_:True)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://acl',headers={'X-Tenant-ID':str(tenant)}) as client:
            response=await client.post('/acl/sociacl/rotation/wallet',json=request)
            assert response.headers['cache-control']=='private, no-store'
            if revocation:
                assert response.status_code==403
                return
            assert response.status_code==200,response.text
            assert set(response.json())=={'attest'}
            assert len(store.read(principal).entries)==1  # Signing never appends.
            policy['activePrincipals']=[];private('policy.json',policy)
            assert (await client.post('/acl/sociacl/rotation/wallet',json=request)).status_code==403
            policy['activePrincipals']=[principal];private('policy.json',policy)
            response=await client.post('/acl/sociacl/rotation/wallet',json=request)
            assert response.status_code==200,response.text
            signed={**request,**response.json()}
            from rotation_publish_source import RotationPublishSource
            import hashlib
            from statement_source import encoded
            publisher=RotationPublishSource(store,policy_at=lambda _:policy,clock=lambda:request['issuedAt'])
            digest=hashlib.sha256(encoded(signed)).hexdigest()
            assert publisher.wallet_rotation_state(principal,digest)['present'] is False
            assert publisher.publish_wallet_rotation(principal,signed)=={'recordHash':digest}
            published=publisher.wallet_rotation_state(principal,digest)
            assert published['present'] is True
            assert published['head']['currentKey']==request['nextKey']
            assert published['head']['sequence']==request['seq']
            assert len(store.read(principal).entries)==2
            assert (await client.post('/acl/sociacl/rotation/wallet',json=request)).status_code==403
    finally:
        for binding in bindings.values():binding.source.store.close()
        store.close()
