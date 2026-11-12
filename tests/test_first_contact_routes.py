import base64
import hashlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from acl_service.interfaces.api.first_contact_routes import router
from acl_service.infrastructure.first_contact_store import LaneCapacity, is_first_contact_path

PATH = '/api/v1/acl/sociacl/first-contact/' + 'ab' * 32 + '/messages'

class Store:
    def __init__(self):
        self.rows = {}
        self.failure = None
    def append(self, lane, payload):
        if self.failure:
            raise self.failure
        digest = hashlib.sha256(payload).hexdigest()
        self.rows[(lane, digest)] = payload
        return digest
    def read(self, lane):
        if self.failure:
            raise self.failure
        return [{'id': digest, 'ciphertext': value} for (key, digest), value in self.rows.items() if key == lane]

@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    app.state.first_contact_store = Store()
    with TestClient(app) as client:
        yield client, app.state.first_contact_store

def test_ciphertext_round_trip_retry_and_lane_isolation(client):
    c, store = client
    payload = bytes(range(256))
    for _ in range(2):
        response = c.post(PATH, content=payload, headers={'Content-Type': 'application/octet-stream'})
        assert response.status_code == 200
        assert response.json() == {'id': hashlib.sha256(payload).hexdigest()}
    response = c.get(PATH, headers={'X-Tenant-ID': 'not-an-identity'})
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == {'messages': [{'id': hashlib.sha256(payload).hexdigest(), 'ciphertext': base64.b64encode(payload).decode()}]}
    assert c.get(PATH.replace('ab' * 32, 'cd' * 32)).json() == {'messages': []}
    assert len(store.rows) == 1

@pytest.mark.parametrize('payload,content_type,status', [(b'a' * 93, 'application/octet-stream', 400),
    (b'a' * 8193, 'application/octet-stream', 413), (b'a' * 94, 'application/json', 415)])
def test_bad_payload_never_reaches_store(client, payload, content_type, status):
    c, store = client
    assert c.post(PATH, content=payload, headers={'Content-Type': content_type}).status_code == status
    assert not store.rows

def test_storage_failure_and_quota_fail_closed(client):
    c, store = client
    store.failure = LaneCapacity()
    response = c.post(PATH, content=b'x' * 94, headers={'Content-Type': 'application/octet-stream'})
    assert response.status_code == 429
    store.failure = OperationalError('query', {}, Exception('offline'))
    assert c.get(PATH).status_code == 503
    assert c.post(PATH, content=b'x' * 94, headers={'Content-Type': 'application/octet-stream'}).status_code == 503

@pytest.mark.parametrize('method,path', [('PUT', PATH), ('DELETE', PATH), ('GET', PATH + '/'),
    ('GET', PATH.replace('ab' * 32, '~pub')), ('GET', PATH.replace('ab' * 32, 'AB' * 32)),
    ('GET', '/api/v1/acl/sociacl/keyring/recovery/rows/id')])
def test_no_broad_public_middleware_bypass(method, path):
    assert not is_first_contact_path(path, method)

@pytest.mark.parametrize('field,limit', [('total', 4096), ('bytes', 32*1024*1024),
    ('lane_total', 128), ('lane_bytes', 1024*1024), ('recent', 10)])
def test_each_quota_refuses_the_next_message(field, limit):
    from acl_service.infrastructure.first_contact_store import require_capacity
    totals = dict(total=0, bytes=0, lane_total=0, lane_bytes=0, recent=0)
    totals[field] = limit
    with pytest.raises(LaneCapacity):
        require_capacity(totals, 94)
    totals[field] -= 94 if field.endswith('bytes') else 1
    require_capacity(totals, 94)

def test_access_log_redacts_lane_and_query():
    import logging
    from acl_service.lane_access_log import LaneAccessLogFilter
    record = logging.LogRecord('uvicorn.access', logging.INFO, '', 0, '%s %s %s %s %s',
        ('client', 'GET', PATH + '?identity=private', '1.1', 200), None)
    assert LaneAccessLogFilter().filter(record)
    assert 'ab' * 32 not in record.getMessage()
    assert 'private' not in record.getMessage()
