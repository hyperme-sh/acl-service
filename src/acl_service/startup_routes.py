"""Authenticated startup policy reconciliation, disabled by default."""
import asyncio
import hmac
import os
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from ._startup_contract import load, fingerprint

router=APIRouter(prefix='/internal/startup')


class Command(BaseModel):
    model_config=ConfigDict(extra='forbid')
    mapping_sha256:str=Field(pattern='^[a-f0-9]{64}$')


@router.post('/reconcile')
async def reconcile(command:Command,request:Request):
    expected=os.environ.get('ACL_STARTUP_TOKEN','')
    if not expected or not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Scoped startup credential required')
    try:
        if os.environ.get('STARTUP_IDENTITY_ENABLED')!='1':raise ValueError('Disabled')
        config=load(Path(os.environ.get('STARTUP_IDENTITY_CONFIG_FILE','')))
        if fingerprint(config)!=command.mapping_sha256:raise ValueError('Mapping differs')
        url=os.environ.get('STARTUP_AUTH_URL','').rstrip('/')
        token=os.environ.get('AUTH_STARTUP_READ_TOKEN','')
        parsed=urlsplit(url)
        local=parsed.hostname in ('localhost','127.0.0.1','::1')
        if (not token or not parsed.hostname or (parsed.scheme!='https' and not (local and parsed.scheme=='http')) or
            parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):raise ValueError('Auth owner endpoint unavailable')
        async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
            response=await client.post(url+'/auth/startup/status',json=command.model_dump(),headers={'Authorization':'Bearer '+token})
            response.raise_for_status()
            person=response.json()
        return await asyncio.to_thread(request.app.state.policy_store.reconcile_startup,config,person)
    except (ValueError,OSError,KeyError,TypeError,httpx.HTTPError):
        raise HTTPException(409,'Startup policy mapping unavailable or conflicting') from None
