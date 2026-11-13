"""Actual ACL writes and delivery transactions, scheduled by Infra only."""
import asyncio
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine,text
from acl_service.infrastructure import atomic,user_created_consumer
from acl_service.interfaces.api import routes,sociacl_routes,events
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.contracts import validate_event_envelope

PRODUCERS=['policy_create','policy_delete','share_create','resolve','evaluate','recovery','consume']


@pytest.fixture
async def fixture():
    path=Path(os.environ['ACL_OUTBOX_FIXTURE_SCRIPT'])
    spec=importlib.util.spec_from_file_location('acl_fixture',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.environment(os.environ)
    def command(action):subprocess.run([sys.executable,str(path),action],check=True,timeout=180)
    command('reset-case')
    root=Path(os.environ['ACL_OUTBOX_FIXTURE_DIR']);engine=create_engine((root/'owner-url').read_text())
    try:
        invoke,state,consumer,envelope=module.handlers(engine)
        yield module.configuration(),command,engine,invoke,state,consumer,envelope
    finally:engine.dispose()


def snapshot(engine,tenant):
    with engine.begin() as db:
        db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':tenant})
        result={table:db.scalar(text('SELECT count(*) FROM '+table)) for table in ('acl_casbin_rules','sociacl_share_links','sociacl_recovery_sessions','service_outbox','event_inbox')}
        result['uses']=list(db.execute(text('SELECT uses_remaining FROM sociacl_share_links ORDER BY id')).scalars())
        envelopes=list(db.execute(text('SELECT envelope FROM service_outbox')).scalars())
        for encoded in envelopes:
            envelope=ControlPlaneEventEnvelope.model_validate(encoded);validate_event_envelope(envelope)
            assert str(envelope.tenant_id)==tenant
        return result


class ForcedRollback(RuntimeError):pass


@pytest.mark.parametrize('producer',PRODUCERS)
@pytest.mark.parametrize('outcome',['commit','rollback','insert_failure','retry'])
async def test_acl_transaction(producer,outcome,fixture,monkeypatch):
    config,command,engine,invoke,state,consumer,envelope=fixture
    before=snapshot(engine,config['tenant_id'])
    if outcome=='insert_failure':command('break-outbox')
    if outcome=='rollback':
        original=atomic.atomic_store
        @contextmanager
        def rollback(store):
            with original(store) as tx:
                yield tx
                raise ForcedRollback('after business and event writes')
        for module in (routes,sociacl_routes,user_created_consumer):monkeypatch.setattr(module,'atomic_store',rollback)
    if outcome=='retry':
        original=atomic.Operation.emit
        def repeat(self,**kwargs):
            result=original(self,**kwargs)
            assert original(self,**kwargs)==result
            return result
        monkeypatch.setattr(atomic.Operation,'emit',repeat)
    if outcome in ('rollback','insert_failure'):
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(ForcedRollback if outcome=='rollback' else IntegrityError):await invoke(producer)
        assert snapshot(engine,config['tenant_id'])==before
    else:
        await invoke(producer)
        if outcome=='retry' and producer in ('policy_create','recovery','consume'):await invoke(producer)
        after=snapshot(engine,config['tenant_id'])
        expected=dict(before);expected['service_outbox']=1
        if producer in ('policy_create','consume'):expected['acl_casbin_rules']+=1
        if producer=='policy_delete':expected['acl_casbin_rules']-=1
        if producer=='share_create':expected['sociacl_share_links']+=1;expected['uses']=[3,3]
        if producer=='evaluate':expected['uses']=[2]
        if producer=='recovery':expected['sociacl_recovery_sessions']+=1
        if producer=='consume':expected['event_inbox']=1
        assert after==expected
    foreign=snapshot(engine,config['other_tenant_id'])
    assert foreign=={**{key:0 for key in before if key!='uses'},'uses':[]}


async def test_http_concurrent_delivery_and_restart_dedupe(fixture):
    config,command,engine,invoke,state,consumer,envelope=fixture
    app=FastAPI();app.include_router(events.router);app.state.event_consumer=consumer
    credential=json.loads(Path(os.environ['EVENT_PRODUCER_TOKENS_FILE']).read_text())['user-service']
    body={'event_id':config['event_id'],'envelope':envelope.model_dump(mode='json')}
    headers={'authorization':'Bearer '+credential,'idempotency-key':config['event_id']}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://acl.fixture') as client:
        responses=await asyncio.gather(*[client.post('/internal/events',json=body,headers=headers) for _ in range(2)])
        assert all(r.status_code==200 for r in responses),[r.text for r in responses]
        assert sorted(r.json()['duplicate'] for r in responses)==[False,True]
        app.state.event_consumer=user_created_consumer.UserCreatedConsumer(state.policy_store)
        retry=await client.post('/internal/events',json=body,headers=headers)
        assert retry.status_code==200 and retry.json()['duplicate']
    result=snapshot(engine,config['tenant_id'])
    assert result['event_inbox']==result['service_outbox']==1
    assert result['acl_casbin_rules']==2


async def test_consumed_identity_cannot_change_payload_or_tenant(fixture):
    config,command,engine,invoke,state,consumer,envelope=fixture
    await invoke('consume')
    before=snapshot(engine,config['tenant_id'])
    for change in ('payload','tenant'):
        changed=envelope.model_copy(deep=True)
        if change=='payload':changed.payload['user_id']=str(uuid.UUID(int=7409))
        else:
            changed.tenant_id=uuid.UUID(config['other_tenant_id']);changed.payload['tenant_id']=config['other_tenant_id']
        with pytest.raises(ValueError,match='reused'):await consumer.receive(uuid.UUID(config['event_id']),changed)
    assert snapshot(engine,config['tenant_id'])==before


async def test_policy_remove_readd_has_distinct_operation_ids(fixture):
    config,command,engine,invoke,state,consumer,envelope=fixture
    from types import SimpleNamespace
    from auth_service.schemas import AuthMeResponse
    from acl_service.domain.dtos import PolicyRuleCreate,PolicyRuleDelete
    from starlette.requests import Request
    tenant=uuid.UUID(config['tenant_id']);actor=AuthMeResponse(sub=config['subject'],tenant_id=tenant)
    request=Request({'type':'http','headers':[],'app':SimpleNamespace(state=state)})
    rule=['fixture-policy','resource','read']
    await invoke('policy_delete')
    await routes.create_policy(PolicyRuleCreate(ptype='p',rule=rule),request,tenant,actor,None)
    await routes.remove_policy(PolicyRuleDelete(ptype='p',rule=rule),request,tenant,actor,None)
    result=snapshot(engine,config['tenant_id'])
    assert result['service_outbox']==3 and result['acl_casbin_rules']==0
