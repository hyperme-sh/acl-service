"""Private immutable reader-wrap records in the application's Spanopticon tenant.

Storage possession is not permission to deliver. Callers must authenticate the
reader and revalidate the current authorization fence after fetching bytes.
"""
import asyncio
import hashlib
import re
import time
from urllib.parse import urlsplit
from uuid import UUID

MAX_WRAP_BYTES = 65_536


class WrapStorageUnavailable(ValueError):
    pass


class WrapStorageConflict(ValueError):
    pass


def _digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


class PrivateWrapStore:
    """Opaque record names only; no principal, object or recipient in URLs.

    This adapter creates immutable records. A lost-response or conflict requires
    the caller to refresh authorization and reconcile by the retained digest;
    the adapter never retries writes or overwrites an existing record.
    """
    def __init__(self, origin, tenant, api_key, *, client=None, clock=time.monotonic):
        parsed = urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.port or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise ValueError('invalid tenant storage origin')
        if str(UUID(tenant)) != tenant or UUID(tenant).int == 0:
            raise ValueError('invalid tenant')
        if type(api_key) is not str or re.fullmatch(r'[\x21-\x7e]{1,4096}', api_key) is None:
            raise ValueError('invalid storage key')
        self.tenant = tenant
        self._base = origin.rstrip('/') + '/api/v1/storage/records/media/'
        self._headers = {'X-Api-Key': api_key, 'X-Tenant-ID': tenant, 'Accept-Encoding': 'identity'}
        self._clock = clock
        if client is None:
            import httpx
            client = httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                  timeout=2.0, limits=httpx.Limits(max_connections=2, max_keepalive_connections=2))
        self._client = client

    async def close(self):
        await self._client.aclose()

    def _path(self, name):
        if not _digest(name):
            raise ValueError('invalid opaque wrap record')
        return self._base + name

    async def read(self, name, revision, *, cancel=lambda: None):
        """Fetch only the exact retained digest, never the provider's new head."""
        path = self._path(name)
        if not _digest(revision):
            raise ValueError('invalid wrap revision')
        deadline = self._clock() + 2.0
        def guard():
            cancel()
            if self._clock() >= deadline:
                raise WrapStorageUnavailable('private wrap storage unavailable')
        try:
            guard()
            async with asyncio.timeout(2.0), self._client.stream('GET', path, headers=self._headers,
                                                               follow_redirects=False, timeout=2.0) as response:
                guard()
                if response.status_code != 200 or response.headers.get('etag') != '"' + revision + '"':
                    raise ValueError()
                if response.headers.get('content-encoding', 'identity') != 'identity':
                    raise ValueError()
                length = response.headers.get('content-length')
                if length is not None and (re.fullmatch(r'[1-9][0-9]{0,5}', length) is None
                                           or int(length) > MAX_WRAP_BYTES):
                    raise ValueError()
                data = bytearray()
                async for chunk in response.aiter_raw(chunk_size=4096):
                    guard()
                    if len(data) + len(chunk) > MAX_WRAP_BYTES:
                        raise ValueError()
                    data.extend(chunk)
                guard()
                if not data or (length is not None and len(data) != int(length)):
                    raise ValueError()
                if hashlib.sha256(data).hexdigest() != revision:
                    raise ValueError()
                return bytes(data)
        except Exception:
            # Do not include provider bodies, URLs, authentication or transport diagnostics.
            raise WrapStorageUnavailable('private wrap storage unavailable') from None

    async def create(self, name, payload, *, cancel=lambda: None):
        path = self._path(name)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_WRAP_BYTES:
            raise ValueError('invalid private wrap size')
        revision = hashlib.sha256(payload).hexdigest()
        deadline = self._clock() + 2.0
        try:
            cancel()
            if self._clock() >= deadline:
                raise ValueError()
            headers = {**self._headers, 'If-None-Match': '*', 'Content-Type': 'application/octet-stream',
                       'Content-Length': str(len(payload))}
            async with asyncio.timeout(2.0), self._client.stream('PUT', path, headers=headers, content=payload,
                                                               follow_redirects=False, timeout=2.0) as response:
                cancel()
                if self._clock() >= deadline:
                    raise ValueError()
                if response.status_code == 412:
                    raise WrapStorageConflict('private wrap record already exists')
                if response.status_code != 201 or response.headers.get('etag') != '"' + revision + '"':
                    raise ValueError()
                return revision
        except WrapStorageConflict:
            raise
        except Exception:
            raise WrapStorageUnavailable('private wrap storage unavailable') from None

    async def create_or_reconcile(self, name, payload, *, cancel=lambda: None):
        """After fresh reservation authorization, reconcile only identical bytes."""
        try:
            return await self.create(name, payload, cancel=cancel)
        except WrapStorageConflict:
            revision = hashlib.sha256(payload).hexdigest()
            if await self.read(name, revision, cancel=cancel) != payload:
                raise WrapStorageConflict('private wrap record differs') from None
            return revision
