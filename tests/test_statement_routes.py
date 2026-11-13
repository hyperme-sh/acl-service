"""HTTP adapter contract; CI only, no live provider or identity mutation."""
import asyncio
import threading
from types import SimpleNamespace
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from acl_service.interfaces.api.statement_routes import router, StatementBinding
from acl_service.deps import get_current_user, require_matched_tenant

@pytest.mark.asyncio
async def test_binding_body_and_source_contract():
    tenant = uuid4(); calls = []; actor = SimpleNamespace(sub='service', scopes=['acl:statements:read','acl:statements:write'])
    class Source:
        production_ready = True
        def read(self, scope, at, guard):
            guard(); calls.append((scope, at)); return {'snapshot': {}, 'fence': 'a'*64}
        def append(self, scope, at, fence, rows, guard):
            guard(); calls.append((scope, at, fence, rows)); return True
    source = Source(); source.tenant = str(tenant)
    app = FastAPI(); app.include_router(router)
    app.state.statement_bindings = {(tenant, 'service', 'forum'): StatementBinding('forum', source)}
    app.state.statement_slots = asyncio.Semaphore(2)
    app.state.rate_limiter = SimpleNamespace(allow=lambda *a: True)
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[require_matched_tenant] = lambda: tenant
    path = '/acl/sociacl/statements/forum/'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://owner') as client:
        actor.sub = 'browser'
        assert (await client.post(path+'snapshot', json={'evaluatedAt':100})).status_code == 403
        actor.sub = 'service'
        source.production_ready = False
        assert (await client.post(path+'snapshot', json={'evaluatedAt':100})).status_code == 503
        source.production_ready = True
        actor.scopes = []
        assert (await client.post(path+'snapshot', json={'evaluatedAt':100})).status_code == 403
        actor.scopes = ['acl:statements:read','acl:statements:write']
        for raw in [b'{"evaluatedAt":100,"evaluatedAt":101}', b'{"evaluatedAt":true}', b'{"evaluatedAt":100,"history":{}}']:
            assert (await client.post(path+'snapshot', content=raw, headers={'Content-Type':'application/json'})).status_code == 400
        assert not calls
        read = await client.post(path+'snapshot', json={'evaluatedAt':100})
        assert read.status_code == 200 and read.headers['cache-control'] == 'private, no-store'
        assert (await client.post(path+'append', json={'evaluatedAt':100,'fence':read.json()['fence'],'rows':[{}]})).json() == {'ok':True}
        source.tenant = str(uuid4())
        assert (await client.post(path+'snapshot', json={'evaluatedAt':100})).status_code == 403

@pytest.mark.asyncio
async def test_timed_out_threads_keep_capacity_until_stopped():
    tenant = uuid4(); release = threading.Event(); started = threading.Event()
    class Source:
        production_ready = True
        def read(self, scope, at, guard):
            started.set(); release.wait(5); guard(); return {}
    source = Source(); source.tenant = str(tenant)
    app = FastAPI(); app.include_router(router)
    app.state.statement_bindings = {(tenant,'service','forum'):StatementBinding('forum',source)}
    app.state.statement_slots = asyncio.Semaphore(1)
    app.state.rate_limiter = SimpleNamespace(allow=lambda *a:True)
    app.dependency_overrides[get_current_user] = lambda:SimpleNamespace(sub='service', scopes=['acl:statements:read','acl:statements:write'])
    app.dependency_overrides[require_matched_tenant] = lambda:tenant
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://owner') as client:
        try:
            response = await client.post('/acl/sociacl/statements/forum/snapshot',json={'evaluatedAt':100})
            assert response.status_code == 503 and started.is_set()
            assert (await client.post('/acl/sociacl/statements/forum/snapshot',json={'evaluatedAt':100})).status_code == 429
        finally: release.set()
        for _ in range(100):
            if not app.state.statement_slots.locked(): break
            await asyncio.sleep(.01)
        assert not app.state.statement_slots.locked()
