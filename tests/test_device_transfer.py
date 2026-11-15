"""Transfer HTTP/configuration units; no external services."""
import asyncio
import copy
import json
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID
import httpx
import pytest
from fastapi import FastAPI
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.domain.device_transfer import request_value
from acl_service.domain.history_store import HistoryConflict, AdmissionRejected
from acl_service.infrastructure.device_transfer_bindings import DeviceTransferBinding, policy_reader, load_device_transfer_bindings
from acl_service.interfaces.api.device_transfer_routes import router

TENANT=UUID('12345678-1234-1234-1234-123456789abc')
OWNER='a'*43+'.'+'b'*43
SCOPE={'tenant':str(TENANT),'application':'app','audience':'test','sourceOrigin':'https://a.example','destinationOrigin':'https://b.example'}
IDENTITY={'principal':OWNER,'pub':OWNER,'epub':OWNER,'rotationSeq':0}
BODY={'scope':SCOPE,'identity':IDENTITY}


def setup():
    app=FastAPI();app.include_router(router)
    user=SimpleNamespace(sub='reader',scopes=['acl:identity:transfer'])
    app.dependency_overrides[get_current_user]=lambda:user
    app.dependency_overrides[require_matched_tenant]=lambda:TENANT
    source=Mock();source.read.return_value={'checkpoint':{'revision':'ab'*32,'validUntil':100000}}
    app.state.device_transfer_bindings={(TENANT,'reader'):DeviceTransferBinding(OWNER,source)}
    app.state.device_transfer_slots=asyncio.Semaphore(2)
    app.state.rate_limiter=SimpleNamespace(allow=lambda *_:True)
    return app,source,user


@pytest.mark.asyncio
async def test_bound_transport_refuses_scope_secrets_and_authority_failure():
    app,source,user=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        async def post(body=BODY):return await client.post('/acl/sociacl/device-transfer/state',json=body)
        response=await post()
        assert response.status_code==200 and response.headers['cache-control']=='private, no-store'
        assert source.read.call_args.args[:3]==(OWNER,SCOPE,IDENTITY)
        for body in ({**BODY,'keyring':'secret'}, {**BODY,'history':{}}, {**BODY,'identity':{**IDENTITY,'rotationSeq':True}}):
            assert (await post(body)).status_code==400
        assert (await post({**BODY,'scope':{**SCOPE,'tenant':'other'}})).status_code==403
        user.scopes=[];assert (await post()).status_code==403
        user.scopes=['acl:identity:transfer'];user.sub='other';assert (await post()).status_code==403
        user.sub='reader'
        for error,code in [(AdmissionRejected(),403),(HistoryConflict(),409),(OSError(),503)]:
            source.read.side_effect=error
            response=await post();assert response.status_code==code and response.headers['cache-control']=='private, no-store'
        source.read.side_effect=None
        assert (await client.post('/acl/sociacl/device-transfer/state',content=b'x'*4097,headers={'content-type':'application/json'})).status_code==413
        app.state.device_transfer_bindings=None;assert (await post()).status_code==503


def test_public_current_shape_binds_session_and_refuses_uploaded_fields():
    binding={'session':'a'*43,'transcript':'b'*43,'expiresAt':100000,'scope':SCOPE,'identity':IDENTITY}
    assert request_value('current',{'binding':binding})[2]==binding
    for extra in ({'history':{}},{'keyring':[]},{'expectedRevision':None}):
        with pytest.raises(ValueError):request_value('current',{'binding':binding,**extra})
    with pytest.raises(ValueError):request_value('current',{'binding':{**binding,'expiresAt':True}})


def test_live_eligibility_policy_and_missing_configuration():
    assert load_device_transfer_bindings({}) is None
    p={'version':1,'from':90,'until':110,'trust':{'jwks':{},'policy':{},'pinnedIss':[]},'scopes':[SCOPE],'activePrincipals':[OWNER]}
    with patch('acl_service.infrastructure.device_transfer_bindings._private_file',side_effect=lambda _:BytesIO(json.dumps(p).encode())):
        reader=policy_reader('/policy')
        assert reader(100)['activePrincipals']==[OWNER]
        p['activePrincipals']=[];assert reader(100)['activePrincipals']==[]
        with pytest.raises(AdmissionRejected):reader(110)
        p['scopes'][0]={**SCOPE,'sourceOrigin':'http://unsafe'}
        with pytest.raises(ValueError):reader(100)
