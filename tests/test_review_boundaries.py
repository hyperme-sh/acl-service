from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid
import casbin
import pytest
from importlib.resources import files
from starlette.requests import Request
from controlplane_db.models import AclCasbinRule
from panopticon_models.sociacl import SociACLRequestContext
from acl_service.domain import sociacl_evaluator as evaluator
from acl_service.infrastructure import share_repo, policy_repo
from acl_service.infrastructure.casbin_adapter import TenantCasbinAdapter
from acl_service.deps import optional_authenticated_user

@pytest.mark.parametrize('trusted', [None, 'verified-subject'])
def test_group_predicate_ignores_caller_subject(monkeypatch, trusted):
    tid = uuid.uuid4()
    link = SimpleNamespace(revoked_at=None, expires_at=None, uses_remaining=None,
        predicate_json={'member_of_group_id': str(uuid.uuid4())}, mode='auto')
    # Use the actual supported release mode from the schema.
    from panopticon_models.sociacl import SociACLShareMode
    link.mode = next(m.value for m in SociACLShareMode if m.value not in ('notify_only', 'negotiate'))
    seen = []
    monkeypatch.setattr(evaluator, '_user_in_group', lambda eng, tenant, sub, group: seen.append(sub) or True)
    decision = evaluator.evaluate_share_access(None, tid, link,
        SociACLRequestContext(sub=str(uuid.uuid4())), authenticated_sub=trusted)
    assert (decision.decision.value == 'allow') == (trusted is not None)
    assert seen == ([] if trusted is None else [trusted])

@pytest.mark.asyncio
async def test_optional_identity_verifies_bearer_and_mfa_path(monkeypatch):
    from auth_service import deps
    claims = AsyncMock(return_value={'sub':'verified', 'tenant_id':str(uuid.uuid4())})
    monkeypatch.setattr(deps, 'get_access_token_claims', claims)
    assert await optional_authenticated_user(Request({'type':'http','headers':[]})) is None
    user = await optional_authenticated_user(Request({'type':'http','headers':[(b'authorization', b'Bearer credential')]}))
    assert user.sub == 'verified'
    claims.assert_awaited_once_with('credential')

@pytest.mark.parametrize('filename,args', [
    ('model_rbac.conf', ('alice','resource','read')),
    ('model_abac.conf', ('alice','resource','read','budget')),
])
@pytest.mark.parametrize('filtered', [False, True])
def test_mixed_model_rows_load_without_cross_model_policies(filename, args, filtered):
    tid = uuid.uuid4()
    rows = [AclCasbinRule(tenant_id=tid, ptype='p',v0='alice',v1='resource',v2='read'),
            AclCasbinRule(tenant_id=tid, ptype='p',v0='alice',v1='resource',v2='read',v3='budget')]
    class Query:
        def filter(self,*args): return self
        def order_by(self,*args): return self
        def all(self): return rows
    adapter = object.__new__(TenantCasbinAdapter)
    adapter._db_class = AclCasbinRule
    adapter._tenant_uuid = tid
    adapter._softdelete_query = lambda query: query
    adapter.filter_query = lambda query, filt: query
    @contextmanager
    def scope(): yield SimpleNamespace(query=lambda model: Query())
    adapter._session_scope = scope
    model = casbin.Model()
    model.load_model_from_text(files('acl_service').joinpath('resources',filename).read_text())
    if filtered: adapter.load_filtered_policy(model, None)
    else: adapter.load_policy(model)
    enforcer = casbin.Enforcer(model)
    assert enforcer.enforce(*args)
    assert len(enforcer.get_policy()) == 1
    assert not enforcer.enforce('stranger', *args[1:])

@pytest.mark.parametrize('module', [share_repo, policy_repo])
def test_refresh_restores_transaction_local_tenant_after_commit(monkeypatch, module):
    tid = uuid.uuid4()
    class Session:
        tenant = None
        refreshed = False
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def execute(self, stmt, params): self.tenant = params['tid']
        def add(self,row): pass
        def commit(self): self.tenant = None
        def refresh(self,row):
            assert self.tenant == str(tid), 'RLS context lost after commit'
            self.refreshed = True
    session = Session()
    monkeypatch.setattr(module, 'Session', lambda eng:session)
    if module is policy_repo:
        monkeypatch.setattr(module, '_find_rule', lambda *args:None)
        module.add_rule(None,tid,'p',['alice','resource','read'])
    else:
        module.create_share(None,tenant_id=tid,resource_kind='document',
            resource_descriptor={},predicate_json={},mode='auto',expires_at=None,
            uses_remaining=None,owner_user_id=None,group_id=None,created_by=None)
    assert session.refreshed

@pytest.mark.asyncio
@pytest.mark.parametrize('identity', ['anonymous', 'foreign', 'matched'])
async def test_share_route_never_uses_payload_identity(monkeypatch, identity):
    from acl_service.interfaces.api import sociacl_routes as routes
    from auth_service.schemas import AuthMeResponse
    from panopticon_models.sociacl import SociACLEvaluateRequest, SociACLDecision
    tid = uuid.uuid4()
    link = SimpleNamespace(id=uuid.uuid4(), tenant_id=tid)
    monkeypatch.setattr(routes, 'lookup_share_by_token_hash', lambda *args:link)
    seen = []
    def evaluate(*args, **kwargs):
        seen.append(kwargs['authenticated_sub'])
        return SociACLDecision(decision='deny',reason_code='test',matched_predicates=[])
    monkeypatch.setattr(routes, 'evaluate_share_access', evaluate)
    publish = AsyncMock()
    monkeypatch.setattr(routes, 'get_tenant_event_publisher', lambda:SimpleNamespace(publish=publish))
    me = None if identity == 'anonymous' else AuthMeResponse(
        sub='verified', tenant_id=tid if identity == 'matched' else uuid.uuid4())
    request = Request({'type':'http','headers':[],
                       'app':SimpleNamespace(state=SimpleNamespace(sync_engine=None))})
    await routes.sociacl_evaluate(SociACLEvaluateRequest(token='test-token',
        context=SociACLRequestContext(sub='spoofed')), request, me)
    expected = 'verified' if identity == 'matched' else None
    assert seen == [expected]
    assert publish.await_args.kwargs['payload']['actor_sub'] == expected
