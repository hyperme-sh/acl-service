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
from acl_service.migrate import install

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
    install(engine)
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


def exercise(restarted):
    check_http()
    print(json.dumps({'startup':'passed','unauthenticated_and_malformed_credentials':'rejected',
                      'restart':restarted,'scope':'Scoped process/DB startup smoke; event transactions are scheduled nightly'}))


if __name__ == '__main__':
    if sys.argv[1] == 'initialize':
        initialize()
    elif sys.argv[1] in ('exercise', 'restarted'):
        exercise(sys.argv[1] == 'restarted')
    else:
        raise ValueError('Unknown probe phase')
