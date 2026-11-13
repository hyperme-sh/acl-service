import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
import pytest
from starlette.requests import Request
from spanopticon_models.sociacl import SociACLEvaluateRequest, SociACLShareMode
from acl_service.interfaces.api import sociacl_routes as routes
from test_share_store import MemoryShareStore, create
from memory_atomic import install

MODE = next(m.value for m in SociACLShareMode if m.value not in ('notify_only', 'negotiate'))


def setup(monkeypatch):
    store = MemoryShareStore()
    tenant = uuid4()
    row, token = create(store, tenant, mode=MODE)
    publisher, _ = install(store)
    request = Request({'type': 'http', 'headers': [], 'app': SimpleNamespace(
        state=SimpleNamespace(share_store=store, membership_reader=None))})
    return store, row, token, publisher, request


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,accepted", [(MODE, "allow"), ("notify_only", "notify_owner")])
async def test_concurrent_evaluation_only_publishes_one_allow(monkeypatch, mode, accepted):
    store, row, token, publisher, request = setup(monkeypatch)
    row = replace(row, mode=mode)
    store.rows[next(iter(store.rows))] = row
    # Force both evaluations to use the same pre-consumption snapshot.
    store.lookup_share_by_token_hash = lambda _: row
    body = SociACLEvaluateRequest(token=token, context={})
    results = await asyncio.gather(*(routes.sociacl_evaluate(body, request, None) for _ in range(2)))
    assert sorted(r.decision.value for r in results) == sorted([accepted, 'deny'])
    decisions = [event['payload']['decision'] for event in publisher.values()]
    assert sorted(decisions) == sorted([accepted, 'deny'])


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['revoked', 'expired', 'failure'])
async def test_changed_share_cannot_publish_approval(monkeypatch, mutation):
    store, row, token, publisher, request = setup(monkeypatch)
    original = store.decrement_uses
    def reserve(tenant, sid):
        if mutation == 'failure':
            raise RuntimeError('storage unavailable')
        key = next(iter(store.rows))
        field = 'revoked_at' if mutation == 'revoked' else 'expires_at'
        store.rows[key] = replace(store.rows[key], **{field: datetime.now(timezone.utc)})
        return original(tenant, sid)
    store.decrement_uses = reserve
    if mutation == 'failure':
        with pytest.raises(RuntimeError, match='storage unavailable'):
            await routes.sociacl_evaluate(SociACLEvaluateRequest(token=token, context={}), request, None)
        assert not publisher
    else:
        decision = await routes.sociacl_evaluate(SociACLEvaluateRequest(token=token, context={}), request, None)
        assert decision.decision.value == 'deny'
        assert next(iter(publisher.values()))['payload']['decision'] == 'deny'


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['lookup_share_by_token_hash', 'decrement_uses', 'evaluate_share_access'])
async def test_slow_store_does_not_block_event_loop(monkeypatch, operation):
    store, row, token, publisher, request = setup(monkeypatch)
    entered, release = Event(), Event()
    target = routes if operation == 'evaluate_share_access' else store
    original = getattr(target, operation)
    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=3), 'Event loop could not release storage worker'
        return original(*args, **kwargs)
    monkeypatch.setattr(target, operation, slow)
    start = time.monotonic()
    task = asyncio.create_task(routes.sociacl_evaluate(SociACLEvaluateRequest(token=token, context={}), request, None))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        # This coroutine can run while storage is blocked in another thread.
        await asyncio.sleep(0)
        assert time.monotonic() - start < 2
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_membership_lookup_reuses_the_mutation_connection(monkeypatch):
    from contextlib import contextmanager
    from auth_service.schemas import AuthMeResponse
    from acl_service.infrastructure import membership_reader
    from memory_atomic import MemoryOperation
    store,row,token,publisher,request=setup(monkeypatch)
    group=uuid4()
    store.rows[next(iter(store.rows))]=replace(row,predicate_json={'member_of_group_id':str(group)})
    request.app.state.membership_reader=membership_reader.PostgresMembershipReader(object())
    binds=[]
    @contextmanager
    def session(bind):
        assert isinstance(bind,MemoryOperation)
        binds.append(bind)
        yield SimpleNamespace(execute=lambda *a,**k:None,
            scalars=lambda *a,**k:SimpleNamespace(first=lambda:object()))
    monkeypatch.setattr(membership_reader,'store_session',session)
    result=await routes.sociacl_evaluate(SociACLEvaluateRequest(token=token,context={}),request,
        AuthMeResponse(sub='verified-member',tenant_id=row.tenant_id))
    assert result.decision.value=='allow'
    assert len(binds)==1 and binds[0].store is store
