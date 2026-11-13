"""Exercise recovery routes with a storage API, without database state on the app."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from auth_service.schemas import AuthMeResponse
from acl_service import deps
from acl_service.interfaces.api import sociacl_routes as routes
from test_recovery_store import MemoryRecoveryStore
from memory_atomic import install


@pytest.mark.asyncio
async def test_recovery_http_retries_return_committed_state(monkeypatch):
    tenant = uuid4()
    app = FastAPI()
    app.state.recovery_store = MemoryRecoveryStore()
    app.include_router(routes.router)
    app.dependency_overrides[deps.require_matched_tenant] = lambda: tenant
    app.dependency_overrides[deps.get_current_user] = lambda: AuthMeResponse(sub='synthetic', tenant_id=tenant)
    events, _ = install(app.state.recovery_store)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        path = routes.router.prefix + '/recovery/sessions'
        first = await client.post(path, json={'idempotency_key': 'synthetic-retry-key'})
        assert first.status_code == 201, first.text
        session_id = first.json()['session_id']
        proof = await client.post(path + '/' + session_id + '/proof', json={})
        assert proof.status_code == 200, proof.text
        retry = await client.post(path, json={'idempotency_key': 'synthetic-retry-key'})
        assert retry.status_code == 201
        assert retry.json() == {**first.json(), 'state': 'awaiting_proof'}
        assert len(events)==1
        assert next(iter(events.values()))['payload']['state']=='pending'


@pytest.mark.asyncio
async def test_storage_failure_cannot_publish_success(monkeypatch):
    class BrokenStore:
        def create_or_get_session(self, *args, **kwargs):
            raise RuntimeError('storage unavailable')
    store=BrokenStore();events,_=install(store)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(recovery_store=store)))
    with pytest.raises(RuntimeError, match='storage unavailable'):
        await routes.sociacl_recovery_create(routes.RecoverySessionCreate(idempotency_key='synthetic-key'),
            request, uuid4(), AuthMeResponse(sub='synthetic'))
    assert not events
