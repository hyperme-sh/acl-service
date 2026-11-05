"""Synthetic checks against a real ACL process and an owned PostgreSQL database."""
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

from sqlalchemy import create_engine, text
from controlplane_db.migrations import upgrade
from api.infrastructure.messaging.tenant_event_publisher import resolve_event_publisher

URL = os.environ['DATABASE_URL']
TENANT_A = uuid.UUID(os.environ['FIXTURE_TENANT_A'])
TENANT_B = uuid.UUID(os.environ['FIXTURE_TENANT_B'])
USER_A = os.environ['FIXTURE_USER_A']
USER_B = os.environ['FIXTURE_USER_B']
USER_C = os.environ['FIXTURE_USER_C']


def eventually(check, description):
    deadline = time.monotonic() + 60
    while True:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(description)
        time.sleep(.5)


def initialize():
    from sqlalchemy.exc import OperationalError
    engine = create_engine(URL, connect_args={'connect_timeout': 1})
    def tcp_ready():
        try:
            with engine.connect() as cx:
                return cx.execute(text('SELECT 1')).scalar() == 1
        except OperationalError:
            return False
    eventually(tcp_ready, 'Disposable PostgreSQL TCP readiness failed')
    engine.dispose()
    upgrade(URL)
    engine = create_engine(URL)
    try:
        with engine.begin() as cx:
            for tenant in (TENANT_A, TENANT_B):
                cx.execute(text('INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)'),
                           {'id': tenant, 'name': 'acl-startup-fixture-' + str(tenant)})
    finally:
        engine.dispose()


def request(path, headers=None):
    req = urllib.request.Request(os.environ['FIXTURE_ACL_URL'] + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.read()


def check_http():
    eventually(lambda: request('/api/v1/health/')[0] == 200, 'Real ACL lifespan did not become ready')
    status, _ = request('/api/v1/health/', {'X-Tenant-ID': 'not-a-uuid'})
    assert status == 400, status
    for authorization in (None, 'Bearer not-a-valid-token'):
        headers = {'X-Tenant-ID': str(TENANT_A)}
        if authorization:
            headers['Authorization'] = authorization
        status, _ = request('/api/v1/acl/policies', headers)
        assert status == 401, (authorization, status)


async def publish(events):
    publisher = resolve_event_publisher(database_url=URL, service_name='acl-owned-startup-fixture',
        service_bus_connection_string=None)
    await publisher.start()
    try:
        for tenant, user in events:
            await publisher.publish(tenant_id=tenant, event_type='user.created.v1',
                payload={'user_id': user, 'email': 'synthetic@example.com', 'tenant_id': str(tenant)},
                correlation_id='acl-startup-' + user)
    finally:
        await publisher.stop()


def exercise(restarted):
    check_http()
    events = [(TENANT_A, USER_A), (TENANT_A, USER_C)] if restarted else [(TENANT_A, USER_A), (TENANT_B, USER_B)]
    asyncio.run(publish(events))
    expected = {(TENANT_A, USER_A), (TENANT_B, USER_B)}
    if restarted:
        expected.add((TENANT_A, USER_C))
    from controlplane_db.models import AclCasbinRule
    from sqlalchemy import select
    engine = create_engine(URL)
    try:
        def processed():
            with engine.connect() as cx:
                rows = cx.execute(select(AclCasbinRule.tenant_id, AclCasbinRule.v0,
                    AclCasbinRule.v1, AclCasbinRule.v2)).all()
                observed = {(r.tenant_id, r.v0) for r in rows}
                if observed != expected:
                    return False
                assert len(rows) == len(expected), 'Duplicate policy after event redelivery'
                assert all(r.v1 == 'user_profile' and r.v2 == 'read' for r in rows)
                counts = dict(cx.execute(text("SELECT tenant_id, count(*) FROM controlplane_events WHERE event_type='acl.policy.updated.v1' GROUP BY tenant_id")).all())
                return counts.get(TENANT_A, 0) >= (3 if restarted else 1) and counts.get(TENANT_B, 0) >= 1
        eventually(processed, 'Real event consumer did not persist tenant policies and publish updates')
    finally:
        engine.dispose()
    print(json.dumps({'startup': 'passed', 'unauthenticated_and_malformed_credentials': 'rejected',
        'postgres_event_roundtrip': 'passed', 'restart_and_redelivery': restarted,
        'scope': 'Disposable admin database fixture; not production RLS or external identity acceptance'}))


if __name__ == '__main__':
    if sys.argv[1] == 'initialize':
        initialize()
    elif sys.argv[1] in ('exercise', 'restarted'):
        exercise(sys.argv[1] == 'restarted')
    else:
        raise ValueError('Unknown probe phase')
