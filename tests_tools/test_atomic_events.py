"""Offline event boundary and nested-session contracts."""
import ast
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


def test_no_shared_bus_publisher_or_log_path_remains():
    root=Path(__file__).resolve().parents[1]/'src/acl_service'
    for path in root.rglob('*.py'):
        source=path.read_text()
        for forbidden in ('get_tenant_event_publisher','PostgresEventPublisher','build_routing_consumer','service_bus_connection_string'):
            assert forbidden not in source
        assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='publish' for n in ast.walk(ast.parse(source)))


@pytest.mark.asyncio
@pytest.mark.parametrize('change,status',[('valid',200),('token',401),('producer',403),('key',400),('oversize',413),('invalid',400),('missing_config',503)])
async def test_http_delivery_authenticates_before_owner_dispatch(tmp_path,monkeypatch,change,status):
    path=tmp_path/'tokens.json';path.write_text(json.dumps({'user-service':'unit-producer-secret'}));monkeypatch.setenv('EVENT_PRODUCER_TOKENS_FILE',str(path))
    consumer=UserCreatedConsumer(None);consumer.receive=AsyncMock(return_value=True)
    app=FastAPI();app.include_router(router);app.state.event_consumer=consumer
    event_id=str(uuid.uuid4());tenant=str(uuid.uuid4())
    body={'event_id':event_id,'envelope':{'service':'user-service','event_type':'user.created.v1','tenant_id':tenant,'payload':{'user_id':str(uuid.uuid4()),'email':'unit@example.com','tenant_id':tenant}}}
    headers={'authorization':'Bearer unit-producer-secret','idempotency-key':event_id}
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
