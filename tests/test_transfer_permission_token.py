"""Real Auth issuance and ACL bearer admission with synthetic owner sources."""
import asyncio
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI
from starlette.requests import Request

from auth_service import scoped_session, transfer_permission, outbox
from auth_service.schemas import AuthMeResponse
from acl_service import nightly
from acl_service.infrastructure.device_transfer_bindings import DeviceTransferBinding
from acl_service.interfaces.api.device_transfer_routes import router
from controlplane_api.config import settings
from test_device_transfer import TENANT, OWNER, BODY


@pytest.mark.asyncio
async def test_auth_issued_transfer_scope_is_checked_by_actual_acl_route(tmp_path,monkeypatch):
    monkeypatch.setattr(settings,'api_key_exchange_jwt_secret','synthetic-transfer-secret-at-least-32-characters')
    monkeypatch.setattr(settings,'oidc_require_mfa',False)
    org=uuid.uuid4()
    member=scoped_session.ScopeGrant(subject='reader',user_id=uuid.uuid4(),network_id='network',
        tenant_id=TENANT,organization_id=org,role='member',can_purchase=False,
        generation='unit-v1',manifest_sha256='a'*64)
    membership=AsyncMock(return_value=member)
    monkeypatch.setattr(scoped_session,'current_scope',membership)
    monkeypatch.setattr(outbox,'publish_auth_event',AsyncMock())
    grant=dict(id='synthetic',issuer='https://issuer.invalid',subject='reader',client='controlplane-frontend',
        tenant=str(TENANT),organization=str(org),scopeGeneration=member.generation,
        scopeManifest=member.manifest_sha256,expiresAt=int(time.time())+600,
        capability=transfer_permission.CAPABILITY)
    path=tmp_path/'grant.json'
    def save(rows):
        path.write_text(json.dumps({'version':1,'grants':rows}));path.chmod(0o600)
    save([grant]);monkeypatch.setenv('AUTH_TRANSFER_GRANTS_FILE',str(path))
    provider={'iss':grant['issuer'],'sub':'reader','azp':grant['client'],'scope':'openid'}
    async def issue(requested):
        response=await scoped_session.scoped_session(
            scoped_session.ScopedRequest(tenant_id=TENANT,organization_id=org,identity_transfer=requested),
            Request({'type':'http','headers':[]}),AuthMeResponse.from_claims(provider),provider)
        return json.loads(response.body)['access_token']
    ordinary=await issue(False);authorized=await issue(True)
    app=FastAPI();app.include_router(router);nightly.install(app)
    source=Mock();source.read.return_value={'checkpoint':{'revision':'ab'*32,'validUntil':100000}}
    app.state.device_transfer_bindings={(TENANT,'reader'):DeviceTransferBinding(OWNER,source)}
    app.state.device_transfer_slots=asyncio.Semaphore(2)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *_:True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://consumer.invalid') as client:
        async def post(token,tenant=str(TENANT)):
            return await client.post('/acl/sociacl/device-transfer/state',json=BODY,
                headers={'Authorization':'Bearer '+token,'X-Tenant-ID':tenant})
        assert (await post(ordinary)).status_code==403
        source.read.assert_not_called()
        assert (await post(authorized)).status_code==200
        assert source.read.call_count==1
        assert (await post(authorized,str(uuid.uuid4()))).status_code==403
        save([])
        assert (await post(authorized)).status_code in (401,403)
        assert source.read.call_count==1
        save([grant]);membership.return_value=None
        assert (await post(authorized)).status_code in (401,403)
        assert source.read.call_count==1
