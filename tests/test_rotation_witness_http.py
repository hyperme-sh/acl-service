"""Prepared transport contracts; ASGI authentication and signing are substituted."""
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.interfaces.api.rotation_witness_routes import router, RotationBinding

TENANT=UUID('12345678-1234-1234-1234-123456789abc')
BODY=dict(v=1,kind='rotate',principal='owner',seq=1,prevKey='old',nextKey='new',nextEpub='epub',
          issuedAt=100,retainedLinks=['link'],authorizer=dict(kind='wallet',link='link',siwe=dict(message='message',signature='signature')),nextSig='signed')


def setup():
    app=FastAPI(); app.include_router(router)
    user=SimpleNamespace(sub='subject',scopes=['acl:identity:rotate'])
    app.dependency_overrides[get_current_user]=lambda:user
    app.dependency_overrides[require_matched_tenant]=lambda:TENANT
    source=Mock();source.attest_wallet_rotation.return_value='signed.attestation.token'
    app.state.rotation_witness_bindings={(TENANT,'subject'):RotationBinding('owner',source)}
    app.state.rotation_witness_slots=asyncio.Semaphore(1)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *_:True)
    return app,source,user


@pytest.mark.asyncio
async def test_subject_scope_and_exact_public_input():
    app,source,user=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        async def post(body=BODY):return await client.post('/acl/sociacl/rotation/wallet',json=body)
        response=await post()
        assert response.status_code==200 and response.json()=={'attest':'signed.attestation.token'}
        assert response.headers['cache-control']=='private, no-store'
        assert source.attest_wallet_rotation.call_args.args==('owner',BODY)
        for body in ({**BODY,'keyring':'secret'},{**BODY,'attest':'existing'},[],
                     {**BODY,'authorizer':{**BODY['authorizer'],'extra':1}},
                     {**BODY,'authorizer':{**BODY['authorizer'],'siwe':{'message':'x','signature':'s','secret':'x'}}}):
            source.reset_mock();assert (await post(body)).status_code==400;source.attest_wallet_rotation.assert_not_called()
        assert (await post({**BODY,'principal':'foreign'})).status_code==403
        user.scopes=[];assert (await post()).status_code==403
        user.scopes=['acl:identity:rotate'];user.sub='foreign';assert (await post()).status_code==403
        user.sub='subject';app.state.rotation_witness_bindings=None;assert (await post()).status_code==503


@pytest.mark.asyncio
async def test_bounds_refusals_capacity_and_guard():
    app,source,user=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        async def post():return await client.post('/acl/sociacl/rotation/wallet',json=BODY)
        for error,status in [(AdmissionRejected('private detail'),403),(HistoryConflict('private detail'),409),(ValueError('private detail'),503)]:
            source.attest_wallet_rotation.side_effect=error
            response=await post();assert response.status_code==status and 'private detail' not in response.text
            assert response.headers['cache-control']=='private, no-store'
        source.attest_wallet_rotation.side_effect=None
        for result in (None,{},'','x'*16385):
            source.attest_wallet_rotation.return_value=result;assert (await post()).status_code==503
        for content,status in [(b'x'*65537,413),(b'{"v":1,"v":1}',400),(b'{"v":NaN}',400)]:
            assert (await client.post('/acl/sociacl/rotation/wallet',content=content,headers={'content-type':'application/json'})).status_code==status
        assert (await client.post('/acl/sociacl/rotation/wallet',json=BODY,headers={'content-encoding':'gzip'})).status_code==415
        await app.state.rotation_witness_slots.acquire();assert (await post()).status_code==429
        app.state.rotation_witness_slots.release()
        app.state.rate_limiter.allow=lambda *_:False;assert (await post()).status_code==429
    # The guard retained by a worker is cancelled after the request returns.
    with pytest.raises(HistoryConflict):source.attest_wallet_rotation.call_args.kwargs['cancel']()


def test_rotation_router_is_disabled_without_bindings():
    from acl_service.app import create_app
    app=create_app()
    assert app.state.rotation_witness_bindings is None


@pytest.mark.asyncio
async def test_timeout_keeps_capacity_until_signing_worker_exits(monkeypatch):
    import threading
    import acl_service.interfaces.api.rotation_witness_routes as routes
    app,source,user=setup()
    started,finish=threading.Event(),threading.Event()
    def blocked(*args,cancel):
        started.set()
        assert finish.wait(5)
        cancel()
        raise AssertionError('cancelled signing must not return')
    async def timed_out(request,work,stopped):
        assert await asyncio.to_thread(started.wait,5)
        raise TimeoutError()
    source.attest_wallet_rotation.side_effect=blocked
    monkeypatch.setattr(routes,'connected_result',timed_out)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
            response=await client.post('/acl/sociacl/rotation/wallet',json=BODY)
            assert response.status_code==503 and app.state.rotation_witness_slots.locked()
    finally:
        finish.set()
        async with asyncio.timeout(5):
            while app.state.rotation_witness_slots.locked():await asyncio.sleep(.01)
