"""ASGI transport units with substituted auth and contact source; no services."""
import asyncio
import base64
from types import SimpleNamespace
from uuid import UUID
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI

from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import HistoryConflict
from acl_service.interfaces.api.contact_routes import ContactBinding, router

OWNER='a'*43+'.'+'b'*43
TENANT=UUID('12345678-1234-1234-1234-123456789abc')


def setup():
    app=FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user]=lambda:SimpleNamespace(sub='reader')
    app.dependency_overrides[require_matched_tenant]=lambda:TENANT
    source=Mock()
    source.read.return_value={'revision':0,'payload':None}
    source.write.return_value={'revision':1,'digest':'ab'*32}
    app.state.contact_bindings={(TENANT,'reader'):ContactBinding(OWNER,source)}
    app.state.contact_slots=asyncio.Semaphore(2)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *args:True)
    return app,source


def body():return {'owner':OWNER,'kind':'vault','evaluatedAt':100}


@pytest.mark.asyncio
async def test_transport_uses_bound_reader_and_returns_no_store():
    app,source=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        response=await client.post('/acl/sociacl/contacts/read',json=body())
    assert response.status_code==200 and response.headers['cache-control']=='private, no-store'
    assert source.read.call_args.args[:5]==(str(TENANT),OWNER,OWNER,'vault',100)


@pytest.mark.asyncio
async def test_write_decodes_only_canonical_bounded_ciphertext():
    app,source=setup()
    value={**body(),'revision':0,'payload':base64.b64encode(b'x'*28).decode(),'signature':'sig'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        assert (await client.post('/acl/sociacl/contacts/write',json=value)).status_code==200
        assert source.write.call_args.args[6]==b'x'*28
        source.write.reset_mock()
        for patch in ({'revision':True},{'revision':-1},{'payload':'bad'},{'signature':None},{'owner':'bad'},{'kind':[]},{'evaluatedAt':True},{'extra':1}):
            assert (await client.post('/acl/sociacl/contacts/write',json={**value,**patch})).status_code==400
    source.write.assert_not_called()


@pytest.mark.asyncio
async def test_absent_bindings_foreign_subject_and_changed_state_refuse():
    app,source=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        source.read.side_effect=HistoryConflict()
        assert (await client.post('/acl/sociacl/contacts/read',json=body())).status_code==409
        app.state.contact_bindings={}
        assert (await client.post('/acl/sociacl/contacts/read',json=body())).status_code==403
        app.state.contact_bindings=None
        assert (await client.post('/acl/sociacl/contacts/read',json=body())).status_code==503
