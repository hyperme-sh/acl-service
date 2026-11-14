"""Bounded one-shot allocation exchange through the tenant Storage gateway."""
import asyncio
import base64
import json
import re
from urllib.parse import urlsplit
from uuid import UUID


class AllocationUnavailable(ValueError):
    pass


class AllocationClient:
    def __init__(self, origin, tenant, api_key, *, client=None):
        parsed=urlsplit(origin)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.port
                or parsed.path or parsed.query or parsed.fragment or str(UUID(tenant))!=tenant or not UUID(tenant).int
                or type(api_key) is not str or not re.fullmatch(r'[\x21-\x7e]{1,4096}',api_key)):
            raise ValueError('Invalid allocation transport configuration')
        self.tenant=tenant
        self._url=origin+'/api/v1/storage/allocations/issue'
        self._headers={'X-Api-Key':api_key,'X-Tenant-ID':tenant,'Accept-Encoding':'identity'}
        if client is None:
            import httpx
            client=httpx.AsyncClient(trust_env=False,follow_redirects=False,timeout=2,
                limits=httpx.Limits(max_connections=2,max_keepalive_connections=2))
        self._client=client

    async def close(self):
        await self._client.aclose()

    async def issue(self, scope, request):
        if scope.tenant!=self.tenant or type(request) is not bytes or not 1<=len(request)<=4096:
            raise AllocationUnavailable('Invalid allocation request')
        body={'object':scope.object,'owner':scope.owner,'ownershipDigest':scope.ownership_digest,
              'request':base64.b64encode(request).decode('ascii')}
        try:
            async with asyncio.timeout(2), self._client.stream('POST',self._url,headers=self._headers,
                    json=body,follow_redirects=False,timeout=2) as response:
                if response.status_code!=200 or response.headers.get('content-encoding','identity')!='identity':
                    raise ValueError()
                length=response.headers.get('content-length')
                if length is not None and (not re.fullmatch(r'[1-9][0-9]{0,3}',length) or int(length)>4096):
                    raise ValueError()
                raw=bytearray()
                async for chunk in response.aiter_raw(chunk_size=4096):
                    if len(raw)+len(chunk)>4096:raise ValueError()
                    raw.extend(chunk)
                if not raw or (length is not None and len(raw)!=int(length)):raise ValueError()
                return bytes(raw)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AllocationUnavailable('Allocation service unavailable; reconcile') from None
