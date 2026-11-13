"""HTTP creator/manager authorization using real policy evaluation and storage APIs."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from auth_service.schemas import AuthMeResponse
from acl_service import deps
from acl_service.interfaces.api import sociacl_routes as routes
from test_policy_store import MemoryPolicyStore
from test_share_store import MemoryShareStore, create
from memory_atomic import install


@pytest.mark.asyncio
async def test_creator_manager_foreign_grants_and_revocation(monkeypatch):
    tenant, foreign, declared_owner = uuid4(), uuid4(), uuid4()
    app = FastAPI()
    app.state.share_store = shares = MemoryShareStore()
    app.state.policy_store = policies = MemoryPolicyStore()
    app.include_router(routes.router)
    viewer = AuthMeResponse(sub='alice', tenant_id=tenant)
    app.dependency_overrides[deps.get_current_user] = lambda: viewer
    app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: viewer.tenant_id
    install(shares)
    own, token = create(shares, tenant, resource_kind='attribute_bundle', created_by='alice')
    other, _ = create(shares, tenant, resource_kind='attribute_bundle', created_by='bob', owner_user_id=declared_owner)
    legacy, _ = create(shares, tenant, resource_kind='attribute_bundle', created_by=None)
    foreign_row, _ = create(shares, foreign, resource_kind='attribute_bundle', created_by='alice')
    path = routes.router.prefix + '/shares'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        async def listing(**params):
            return await client.get(path, headers={'X-Tenant-ID': str(tenant)}, params=params)
        result = await listing(creator_sub='bob', manager='true')
        assert result.status_code == 200
        assert [r['share_id'] for r in result.json()] == [str(own.id)]
        assert token not in result.text and 'token_hash' not in result.text
        viewer = AuthMeResponse(sub=str(declared_owner), tenant_id=tenant)
        assert (await listing()).json() == []  # Owner UUID is not a verified subject mapping.
        viewer = AuthMeResponse(sub='manager', tenant_id=tenant)
        grant = ['user:manager', '/acl/sociacl/shares', 'manage']
        policies.add_rule(foreign, 'p', grant)
        assert (await listing()).json() == []
        policies.add_rule(tenant, 'p', grant)
        result = await listing()
        assert {r['share_id'] for r in result.json()} == {str(r.id) for r in (own, other, legacy)}
        assert str(foreign_row.id) not in result.text
        policies.delete_rule(tenant, 'p', grant)
        assert (await listing()).json() == []
        viewer = AuthMeResponse(sub='alice', tenant_id=foreign)
        assert (await listing()).status_code == 403
        viewer = AuthMeResponse(sub='alice', tenant_id=tenant)
        created = await client.post(path, headers={'X-Tenant-ID': str(tenant)}, json={
            'resource_kind': 'attribute_bundle', 'mode': 'release_if_match',
            'resource_descriptor': {}, 'predicate': {}, 'created_by': 'bob'})
        assert created.status_code == 201, created.text
        rows = (await listing()).json()
        assert {r['created_by'] for r in rows} == {'alice'}


@pytest.mark.asyncio
async def test_policy_failure_does_not_fall_back_to_tenant_listing():
    class BrokenPolicies:
        def list_rules(self, tenant):
            raise RuntimeError('policy unavailable')
    class Shares:
        def list_shares(self, *args, **kwargs):
            pytest.fail('Storage must not be read after authorization failure')
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        share_store=Shares(), policy_store=BrokenPolicies())))
    with pytest.raises(RuntimeError, match='policy unavailable'):
        await routes.sociacl_list_shares(request, uuid4(), AuthMeResponse(sub='alice'))
