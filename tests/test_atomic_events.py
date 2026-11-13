"""Offline event boundary and nested-session contracts."""
import json
from pathlib import Path
from unittest.mock import AsyncMock
import uuid
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine,text
from acl_service.infrastructure.atomic import store_session
from acl_service.infrastructure.user_created_consumer import UserCreatedConsumer
from acl_service.interfaces.api.events import router


def test_local_session_commit_cannot_commit_outer_transaction():
    # In-memory SQLite exercises SQLAlchemy's savepoint contract, not service SQL.
    engine=create_engine('sqlite://')
    with engine.connect() as db:
        db.exec_driver_sql('CREATE TABLE unit_value(id INTEGER)');db.commit()
        db.exec_driver_sql('BEGIN')
        with store_session(db) as session:
            session.execute(text('INSERT INTO unit_value VALUES (1)'));session.commit()
        db.rollback()
        assert db.scalar(text('SELECT count(*) FROM unit_value'))==0
    engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('change,status',[('valid',200),('token',401),('producer',403),('key',400),('oversize',413),('invalid',400),('missing_config',503),('missing_time',400)])
async def test_http_delivery_authenticates_before_owner_dispatch(tmp_path,monkeypatch,change,status):
    path=tmp_path/'tokens.json';path.write_text(json.dumps({'user-service':'unit-producer-secret'}));monkeypatch.setenv('EVENT_PRODUCER_TOKENS_FILE',str(path))
    consumer=UserCreatedConsumer(None);consumer.receive=AsyncMock(return_value=True)
    app=FastAPI();app.include_router(router);app.state.event_consumer=consumer
    event_id=str(uuid.uuid4());tenant=str(uuid.uuid4())
    body={'event_id':event_id,'envelope':{'occurred_at':'2026-11-12T00:00:00Z','service':'user-service','event_type':'user.created.v1','tenant_id':tenant,'payload':{'user_id':str(uuid.uuid4()),'email':'unit@example.com','tenant_id':tenant}}}
    headers={'authorization':'Bearer unit-producer-secret','idempotency-key':event_id}
    if change=='missing_time':body['envelope'].pop('occurred_at')
    if change=='token':headers['authorization']='Bearer wrong'
    if change=='producer':body['envelope']['service']='other-service'
    if change=='key':headers['idempotency-key']=str(uuid.uuid4())
    if change=='oversize':headers['content-length']='262145'
    if change=='invalid':body={'unexpected':True}
    if change=='missing_config':monkeypatch.delenv('EVENT_PRODUCER_TOKENS_FILE')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        response=await client.post('/internal/events',json=body,headers=headers)
    assert response.status_code==status,response.text
    assert consumer.receive.await_count==int(status==200)


def test_migration_grants_existing_runtime_roles_without_delete():
    from unittest.mock import MagicMock
    from sqlalchemy.dialects.postgresql import dialect
    from acl_service.migrate import install
    engine=MagicMock();db=engine.begin.return_value.__enter__.return_value
    db.dialect=dialect();db.scalar.side_effect=[1,None]
    install(engine)
    roles=[call.args[1]['role'] for call in db.scalar.call_args_list]
    assert roles==['controlplane','controlplane_app']
    grants=[call.args[0] for call in db.exec_driver_sql.call_args_list if call.args[0].startswith('GRANT')]
    assert grants==[
        'GRANT USAGE ON SCHEMA public TO "controlplane"',
        'GRANT SELECT, INSERT ON event_inbox, service_outbox, service_tenants TO "controlplane"',
        'GRANT UPDATE (delivered_at) ON service_outbox TO "controlplane"',
    ]


@pytest.mark.asyncio
async def test_identical_http_delivery_retries_acknowledge_one_owner_operation(tmp_path,monkeypatch):
    from memory_atomic import install
    from test_policy_store import MemoryPolicyStore
    from test_user_created_consumer import fact
    path=tmp_path/'tokens.json'
    path.write_text(json.dumps({'user-service':'unit-producer-secret'}))
    monkeypatch.setenv('EVENT_PRODUCER_TOKENS_FILE',str(path))
    store=MemoryPolicyStore();events,inbox=install(store)
    app=FastAPI();app.include_router(router);app.state.event_consumer=UserCreatedConsumer(store)
    event_id=str(uuid.uuid4())
    body={'event_id':event_id,'envelope':fact().model_dump(mode='json')}
    headers={'authorization':'Bearer unit-producer-secret','idempotency-key':event_id}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        first=await client.post('/internal/events',json=body,headers=headers)
        retry=await client.post('/internal/events',json=body,headers=headers)
    assert first.status_code==retry.status_code==200
    assert not first.json()['duplicate'] and retry.json()['duplicate']
    assert len(store.rows)==len(events)==len(inbox)==1
