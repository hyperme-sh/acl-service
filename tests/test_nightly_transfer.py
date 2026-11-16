"""Native transfer handler and worker; registry, provider and source are substituted."""
import asyncio
import json
import threading
from uuid import UUID
import httpx
import pytest
from controlplane_identity import nightly
from controlplane_identity.nightly_http import Authority, RunMiddleware
from test_device_transfer import setup, BODY, TENANT

SUB='11111111-1111-4111-8111-111111111111'
ORIGIN='https://portal.test.hyperme.sh'
PATH='/acl/sociacl/device-transfer/state'
SCOPE=dict(suite='portal-device-transfer',subject=SUB,tenant=str(TENANT),organization='',realm='controlplane',issuer='https://auth.test.hyperme.sh/realms/controlplane',clients=['controlplane-frontend'],origins=[ORIGIN],identities={'sea':[]})
BINDING=dict(version=1,owner='acl',run='123-1-portal-device-transfer',generation='c'*64,scope=SCOPE,operation='33333333-3333-4333-8333-333333333333')
CONFIG=dict(version=1,owner='acl',origin='https://api.test.hyperme.sh',authOrigin='https://api.test.hyperme.sh',ownerKey='a'*64,controllerKey='b'*64,scopes={SCOPE['suite']:SCOPE})


def prepared(monkeypatch):
    monkeypatch.setattr(nightly,'_subjects',frozenset())
    app,source,user=setup();user.sub=SUB
    app.state.device_transfer_bindings[(TENANT,SUB)]=app.state.device_transfer_bindings.pop((TENANT,'reader'))
    calls=[];active=[True]
    def registry(request):
        value=json.loads(request.content);calls.append(value['action'])
        if value['action']=='admit':return httpx.Response(200,json=BINDING) if active[0] else httpx.Response(409)
        assert value['action']=='complete'
        return httpx.Response(200,json={k:BINDING[k] for k in ('version','owner','run','generation','operation')}|{'completed':True})
    app.add_middleware(RunMiddleware,authority=Authority(CONFIG,'acl',httpx.MockTransport(registry)),paths={('POST',PATH)},control_path='/internal/nightly-run')
    body=BODY|{'scope':BODY['scope']|{'sourceOrigin':ORIGIN,'destinationOrigin':ORIGIN}}
    return app,source,body,calls,active


@pytest.mark.asyncio
async def test_native_worker_finishes_before_terminal_completion(monkeypatch):
    app,source,body,calls,active=prepared(monkeypatch)
    entered=threading.Event();finish=threading.Event()
    def read(*args):
        args[-1]();entered.set();assert finish.wait(3);args[-1]()
        return {'checkpoint':{'revision':'a'*64,'validUntil':100000}}
    source.read.side_effect=read
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://api.test.hyperme.sh') as client:
        task=asyncio.create_task(client.post(PATH,json=body,headers={'X-Nightly-Run-Grant':'d'*64}))
        assert await asyncio.to_thread(entered.wait,3)
        assert calls==['admit'];active[0]=False;finish.set()
        assert (await task).status_code==200
        assert calls==['admit','complete']
        assert (await client.post(PATH,json=body,headers={'X-Nightly-Run-Grant':'d'*64})).status_code==409
        assert source.read.call_count==1


@pytest.mark.asyncio
async def test_foreign_origin_never_reaches_native_source(monkeypatch):
    app,source,body,calls,_=prepared(monkeypatch)
    body['scope']['destinationOrigin']='https://foreign.invalid'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://api.test.hyperme.sh') as client:
        assert (await client.post(PATH,json=body,headers={'X-Nightly-Run-Grant':'d'*64})).status_code==409
    source.read.assert_not_called();assert calls==['admit']


@pytest.mark.asyncio
async def test_direct_optional_auth_refuses_introspected_original_run(monkeypatch):
    from starlette.requests import Request
    from fastapi import HTTPException
    from acl_service.deps import optional_authenticated_user
    from auth_service import deps
    async def introspected(token):
        return {'sub':SUB,'nightly_run':{k:BINDING[k] for k in ('run','generation')}}
    monkeypatch.setattr(deps,'get_access_token_claims',introspected)
    with pytest.raises(HTTPException) as caught:
        await optional_authenticated_user(Request({'type':'http','headers':[(b'authorization',b'Bearer native-token')]}))
    assert caught.value.status_code==403
