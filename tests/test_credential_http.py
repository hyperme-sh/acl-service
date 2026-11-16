"""Authenticated credential transport contracts, CI only."""
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.credential_bindings import CredentialBinding
from acl_service.interfaces.api.credential_routes import router

TENANT=UUID('12345678-1234-1234-1234-123456789abc')
BODY={'credential':{'kind':'wallet','address':'address'},'evaluatedAt':100}

@pytest.mark.asyncio
async def test_bound_domain_transport_and_failures():
    app=FastAPI();app.include_router(router)
    user=SimpleNamespace(sub='issuer',scopes=['acl:identity:credential-source'])
    app.dependency_overrides[get_current_user]=lambda:user
    app.dependency_overrides[require_matched_tenant]=lambda:TENANT
    source=Mock(production_ready=True);source.read.return_value={'version':1}
    app.state.credential_bindings={(TENANT,'issuer'):CredentialBinding(source)}
    app.state.credential_slots=asyncio.Semaphore(2)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *_:True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        async def post(body=BODY):return await client.post('/acl/sociacl/credential-source/read',json=body)
        response=await post()
        assert response.status_code==200 and response.headers['cache-control']=='private, no-store'
        assert source.read.call_args.args[:2]==(BODY['credential'],100)
        for body in ({**BODY,'principal':'other'},{**BODY,'tenant':str(TENANT)},{**BODY,'evaluatedAt':True},{**BODY,'history':{}}):
            assert (await post(body)).status_code==400
        user.sub='other';assert (await post()).status_code==403
        user.sub='issuer';user.scopes=[];assert (await post()).status_code==403
        user.scopes=['acl:identity:credential-source']
        for error,code in [(AdmissionRejected(),403),(HistoryConflict(),409),(OSError(),503)]:
            source.read.side_effect=error
            assert (await post()).status_code==code
        source.read.side_effect=None;source.production_ready=False
        assert (await post()).status_code==503
        source.production_ready=True
        assert (await client.post('/acl/sociacl/credential-source/read',content=b'x'*4097,headers={'content-type':'application/json'})).status_code==413
        app.state.credential_bindings=None;assert (await post()).status_code==503
