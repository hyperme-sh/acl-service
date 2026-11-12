import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import httpx
from fastapi import FastAPI
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from acl_service.startup_routes import router
from acl_service._startup_contract import fingerprint


class RouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_configuration_authentication_and_owner_failures(self):
        import tempfile
        config=json.loads((ROOT/'tests/fixtures/startup-identity.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';path.write_text(json.dumps(config))
            env={'STARTUP_IDENTITY_ENABLED':'1','STARTUP_IDENTITY_CONFIG_FILE':str(path),'ACL_STARTUP_TOKEN':'writer',
                'STARTUP_AUTH_URL':'https://auth.example.invalid','AUTH_STARTUP_READ_TOKEN':'reader'}
            app=FastAPI();app.include_router(router)
            calls=[]
            def reconcile(c,p):calls.append((c,p));return {'status':'reconciled'}
            app.state.policy_store=SimpleNamespace(reconcile_startup=reconcile)
            factory=httpx.AsyncClient
            upstream=[]
            def respond(request):
                upstream.append(request)
                self.assertEqual(request.headers['authorization'],'Bearer reader')
                return httpx.Response(503 if len(upstream)==1 else 200,json={'status':'bound'})
            import acl_service.startup_routes as routes
            peer=SimpleNamespace(HTTPError=httpx.HTTPError,AsyncClient=lambda **kw:factory(transport=httpx.MockTransport(respond),**kw))
            async with factory(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
                with patch.dict('os.environ',env,clear=True),patch.object(routes,'httpx',peer):
                    async def send(token='writer',stamp=None):
                        return await client.post('/internal/startup/reconcile',headers={'Authorization':'Bearer '+token},json={'mapping_sha256':stamp or fingerprint(config)})
                    self.assertEqual((await send('browser')).status_code,401)
                    with patch.dict('os.environ',{'STARTUP_IDENTITY_ENABLED':'0'}):self.assertEqual((await send()).status_code,409)
                    self.assertEqual((await send(stamp='0'*64)).status_code,409)
                    self.assertFalse(upstream);self.assertFalse(calls)
                    self.assertEqual((await send()).status_code,409)
                    self.assertFalse(calls)
                    self.assertEqual((await send()).status_code,200)
                    self.assertEqual(len(calls),1)
