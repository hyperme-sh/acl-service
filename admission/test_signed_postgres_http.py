"""Native signed recovery contracts on a CI-owned PostgreSQL source.

Authentication is substituted at the ASGI dependency; native signatures,
protected policy parsing, storage, checkpoints and restart reads are real.
"""
from contextlib import asynccontextmanager
import json
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from acl_service import deps
from acl_service.app import create_app
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore
from acl_service.infrastructure.postgres_media_provision import provision_empty_media_source
from acl_service.infrastructure.signed_store_bindings import load_signed_store_bindings
from api.core import config as api_config
from auth_service.schemas import AuthMeResponse
from history_admission import EnrollmentGrant, HistoryAdmission
from signed_store_source import SignedStoreSource


@pytest.mark.asyncio
@pytest.mark.parametrize("restricted_role", [False, True])
async def test_protected_recovery_restart_and_policy_refusal(tmp_path, migrated_sync_url, monkeypatch, restricted_role):
    base = Path(__file__).parent
    identity = json.loads((base / 'fixture.json').read_bytes())
    operations = json.loads((base / 'store-fixture.json').read_bytes())
    principal, now = identity['genesis'], identity['now']
    token = uuid4().hex
    spec = dict(history_schema='acl_h_' + token, checkpoint_schema='acl_c_' + token,
                tenant=str(uuid4()), source=str(uuid4()))
    tenant = UUID(spec['tenant'])
    provision_empty_media_source(migrated_sync_url, **spec)
    runtime_url = migrated_sync_url
    role = 'acl_recovery_' + token
    if restricted_role:
        password = uuid4().hex
        engine = create_engine(migrated_sync_url)
        try:
            with engine.begin() as connection:
                # Identifiers and password are generated lowercase hex, never input.
                connection.exec_driver_sql(f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE")
                for field in ('history_schema', 'checkpoint_schema'):
                    schema = spec[field]
                    connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {role}')
                    connection.exec_driver_sql(f'GRANT SELECT ON ALL TABLES IN SCHEMA "{schema}" TO {role}')
                    connection.exec_driver_sql(f'GRANT UPDATE ON "{schema}".source_marker TO {role}')
                history, checkpoint = spec['history_schema'], spec['checkpoint_schema']
                for schema, table in ((history, 'history_ciphertext'), (history, 'history_head_floors'),
                                      (checkpoint, 'ciphertext_heads')):
                    connection.exec_driver_sql(f'GRANT INSERT, UPDATE ON "{schema}".{table} TO {role}')
                connection.exec_driver_sql(f'GRANT UPDATE ON "{checkpoint}".authority_checkpoint TO {role}')
        finally:
            engine.dispose()
        runtime_url = make_url(migrated_sync_url).set(username=role, password=password).render_as_string(hide_password=False)
        engine = create_engine(runtime_url)
        try:
            with engine.begin() as connection, pytest.raises(ProgrammingError):
                connection.exec_driver_sql(f'CREATE TABLE "{spec["history_schema"]}".forbidden (id INTEGER)')
        finally:
            engine.dispose()
    trust = {key: identity[key] for key in ('policy', 'jwks', 'pinnedIss')}
    policy = dict(version=1, **{'from':now-1}, until=now+60,
                  trust=trust, activePrincipals=[principal])
    def private(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return str(path)
    policy_path = private('policy.json', policy)
    postgres_path = private('postgres.json', dict(version=1, databaseUrl=runtime_url,
        historySchema=spec['history_schema'], checkpointSchema=spec['checkpoint_schema'],
        tenant=spec['tenant'], source=spec['source']))
    bindings_path = private('bindings.json', dict(version=1, bindings=[dict(
        tenant=spec['tenant'], subject='owner', principal=principal,
        postgresFile=postgres_path, policyFile=policy_path)]))
    grant = EnrollmentGrant(principal, 'qualification', 'one-use-grant', now+60)
    def admission(store):
        return HistoryAdmission(store, grant_for=lambda _:grant, clock=lambda:now,
                                trust_at=lambda _:trust)
    store = PostgresHistoryStore(migrated_sync_url, **spec)
    try:
        admission(store).enroll(principal, json.dumps(identity['binding']).encode(), identity['signature'])
    finally:
        store.close()
    monkeypatch.setattr(api_config.settings, 'database_url', migrated_sync_url.replace('+psycopg', ''))
    monkeypatch.setattr(api_config.settings, 'acl_rate_limit_per_minute', 100)

    class LoseWriteResponse(httpx.ASGITransport):
        async def handle_async_request(self, request):
            response = await super().handle_async_request(request)
            if request.method == 'POST' and response.status_code == 200:
                await response.aclose()
                raise httpx.ReadError('synthetic return-path loss', request=request)
            return response

    @asynccontextmanager
    async def restart():
        bindings = load_signed_store_bindings({'SOCIACL_SIGNED_STORE_BINDINGS_FILE':bindings_path},
            source_factory=lambda settings, reader:SignedStoreSource(settings.open(), reader, clock=lambda:now))
        source = bindings[(tenant, 'owner')].writer
        app = create_app(test_event_sink=[], signed_store_bindings=bindings)
        app.dependency_overrides[deps.get_current_user] = lambda:AuthMeResponse(sub='owner', tenant_id=tenant)
        app.dependency_overrides[deps.get_current_tenant_from_token] = lambda:tenant
        try:
            async with LifespanManager(app), httpx.AsyncClient(transport=LoseWriteResponse(app=app),
                base_url='http://acl/api/v1/acl/sociacl/keyring/recovery/',
                headers={'X-Tenant-ID':str(tenant)}) as client:
                yield client, source
        finally:
            source.store.close()

    async def lost(client, name):
        with pytest.raises(httpx.ReadError, match='synthetic return-path loss'):
            await client.post('operations', json=operations[name])

    async def expect(client, generation, current, pending):
        for slot, name in (('current', current), ('pending', pending)):
            response = await client.get('rows/' + slot)
            assert response.status_code == 200
            assert response.headers['cache-control'] == 'no-store'
            assert response.json()['generation'] == generation
            assert response.json()['row'] == (operations[name]['row'] if name else None)

    try:
        async with restart() as (client, _):
            await lost(client, 'current')
        async with restart() as (client, source):
            await expect(client, 1, 'current', None)
            policy['activePrincipals'] = []
            private('policy.json', policy)
            assert (await client.get('rows/current')).status_code == 403
            assert (await client.post('operations', json=operations['pending'])).status_code == 403
            assert source.store.read_ciphertext(principal, 'recovery')[0] == 1
            policy['activePrincipals'] = [principal]
            private('policy.json', policy)
            await lost(client, 'pending')
        async with restart() as (client, source):
            await expect(client, 2, 'current', 'pending')
            authority = PostgresHistoryStore(migrated_sync_url, **spec)
            try:
                for name in ('wallet', 'rotate-v4-wallet'):
                    admission(authority).admit(principal, json.dumps(identity[name]).encode())
            finally:
                authority.close()
            await lost(client, 'commit')
        async with restart() as (client, _):
            await expect(client, 3, 'pending', None)
            await lost(client, 'deleteCommitted')
        async with restart() as (client, _):
            await expect(client, 4, None, None)
    finally:
        engine = create_engine(migrated_sync_url)
        try:
            with engine.begin() as connection:
                for field in ('history_schema', 'checkpoint_schema'):
                    connection.execute(text(f'DROP SCHEMA IF EXISTS "{spec[field]}" CASCADE'))
                if restricted_role:
                    connection.exec_driver_sql(f'DROP ROLE {role}')
        finally:
            engine.dispose()
