"""Owner HTTP delivery endpoint, compatible with the shared outbox relay."""
import hmac
import json
import os
from pathlib import Path
import uuid
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from controlplane_events.envelope import ControlPlaneEventEnvelope
from acl_service.infrastructure.atomic import MAX_DELIVERY_BYTES
from acl_service.infrastructure.user_created_consumer import UserCreatedConsumer

router=APIRouter()


class Delivery(BaseModel):
    model_config=ConfigDict(extra='forbid')
    event_id:uuid.UUID
    envelope:ControlPlaneEventEnvelope

    @model_validator(mode='before')
    @classmethod
    def require_sender_time(cls, value):
        envelope=value.get('envelope') if isinstance(value,dict) else None
        if not isinstance(envelope,dict) or not envelope.get('occurred_at'):
            raise ValueError('Sender timestamp required')
        return value


@router.post('/internal/events')
async def receive_event(request:Request):
    path=os.environ.get('EVENT_PRODUCER_TOKENS_FILE')
    if not path:raise HTTPException(503,'Event credentials not configured')
    try:
        config=json.loads(Path(path).read_text())
        expected=config['user-service']
        if not isinstance(expected,str) or not expected:raise ValueError('Missing token')
    except (OSError,ValueError,KeyError,TypeError):
        raise HTTPException(503,'Event credentials unavailable') from None
    if not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Producer credential required')
    size=request.headers.get('content-length')
    if size is not None:
        try:declared=int(size)
        except ValueError:raise HTTPException(400,'Invalid Content-Length') from None
        if declared<0 or declared>MAX_DELIVERY_BYTES:raise HTTPException(413,'Delivery size refused')
    raw=bytearray()
    async for chunk in request.stream():
        if len(raw)+len(chunk)>MAX_DELIVERY_BYTES:raise HTTPException(413,'Delivery size refused')
        raw.extend(chunk)
    try:delivery=Delivery.model_validate_json(bytes(raw))
    except ValidationError:raise HTTPException(400,'Invalid delivery') from None
    if delivery.envelope.service!='user-service':raise HTTPException(403,'Producer identity differs')
    if request.headers.get('idempotency-key')!=str(delivery.event_id):raise HTTPException(400,'Idempotency key differs')
    consumer=getattr(request.app.state,'event_consumer',None)
    if not isinstance(consumer,UserCreatedConsumer):raise HTTPException(503,'Owner consumer unavailable')
    try:created=await consumer.receive(delivery.event_id,delivery.envelope)
    except ValueError as exc:raise HTTPException(409,str(exc)) from exc
    return {'committed':True,'duplicate':not created,'event_id':str(delivery.event_id)}
