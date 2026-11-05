"""Real application routing and PostgreSQL acceptance for signed public delivery."""
import base64
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError

from acl_service.app import create_app
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_policy_publication import (
    CONFIG_NAMES, PUBLIC_POLICY_PATH, load_publication, read_regular_file,
)
from acl_service.infrastructure.witness_policy_repo import read_policy
from test_witness_policy_ingest import ROOT_KEY, AUDIENCE, bundle, document, sign
from test_witness_policy_repo import engine  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401


def configure(tmp_path, monkeypatch, signed=None):
    payload, signature = signed or bundle()
    paths = [tmp_path / name for name in ('policy.json', 'policy.sig', 'root.pem')]
    paths[0].write_bytes(payload)
    paths[1].write_bytes(signature)
    paths[2].write_bytes(ROOT_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    for name, value in zip(CONFIG_NAMES, [*(str(p) for p in paths), AUDIENCE]):
        monkeypatch.setenv(name, value)
    return payload, signature, paths


def client(engine, publication):
    # Production router and middleware, without startup side effects. Lifecycle
    # wiring is exercised separately below with the real application lifespan.
    app = create_app(test_event_sink=[])
    app.state.sync_engine = engine
    app.state.witness_policy_publication = publication
    return TestClient(app)


def installed(engine, signed):
    return ingest.install_signed_policy(engine, *signed, ROOT_KEY.public_key(), AUDIENCE)


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def unavailable(response):
    assert response.status_code == 503
    assert response.json() == {'error': 'witness-policy-unavailable'}
    assert response.headers['cache-control'] == 'no-store'


def test_disabled_route_needs_no_tenant_session_or_database(monkeypatch):
    import acl_service.middleware as middleware
    monkeypatch.setattr(middleware, 'get_session_maker', lambda: pytest.fail('tenant DB accessed'))
    assert load_publication({}) is None
    response = client(None, None).get(PUBLIC_POLICY_PATH)
    assert response.status_code == 404
    assert response.json() == {'error': 'not-found'}
    assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('case', ['partial', 'relative', 'missing-root', 'private-root', 'wrong-curve', 'oversized-root'])
def test_bad_configuration_fails_startup_without_details(tmp_path, monkeypatch, case):
    _, _, paths = configure(tmp_path, monkeypatch)
    if case == 'partial': monkeypatch.delenv(CONFIG_NAMES[1])
    if case == 'relative': monkeypatch.setenv(CONFIG_NAMES[0], 'relative.json')
    if case == 'missing-root': paths[2].unlink()
    if case == 'private-root': paths[2].write_bytes(ROOT_KEY.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if case == 'wrong-curve': paths[2].write_bytes(ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    if case == 'oversized-root': paths[2].write_bytes(b'x' * 16385)
    with pytest.raises(RuntimeError, match='^Invalid witness policy publication configuration$'):
        load_publication()


def test_nonregular_publication_file_rejected_without_blocking(tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='regular file required'):
        read_regular_file(fifo, 64)


def test_public_delivery_preserves_bytes_and_ignores_request_trust_overrides(engine, tmp_path, monkeypatch):
    payload = json.dumps(document(), indent=2).encode() + b'\n'
    signature = sign(payload)
    configure(tmp_path, monkeypatch, (payload, signature))
    installed(engine, (payload, signature))
    before = read_policy(engine)
    http = client(engine, load_publication())
    response = http.get(PUBLIC_POLICY_PATH + '?audience=attacker&revision=999&root=attacker',
                        headers={'If-None-Match': '*', 'X-Tenant-ID': 'not-a-tenant'})
    assert response.status_code == 200
    assert set(response.json()) == {'type', 'payload', 'signature'}
    assert decode(response.json()['payload']) == payload
    assert decode(response.json()['signature']) == signature
    assert response.headers['cache-control'] == 'no-store'
    assert 'etag' not in response.headers
    assert read_policy(engine) == before


@pytest.mark.parametrize('case', ['absent', 'superseded', 'future', 'conflicting', 'expired',
                                  'bad-signature', 'wrong-audience', 'wrong-root',
                                  'missing-file', 'oversized-payload', 'oversized-signature', 'database'])
def test_unavailable_or_untrusted_artifact_never_served(engine, tmp_path, monkeypatch, case):
    payload, signature, paths = configure(tmp_path, monkeypatch)
    if case != 'absent': installed(engine, (payload, signature))
    before = read_policy(engine)
    if case == 'superseded':
        d = document(); d.update(revision=2, jwks={'keys': []})
        installed(engine, bundle(d)); before = read_policy(engine)
    if case in ('future', 'conflicting', 'expired', 'wrong-audience'):
        d = json.loads(payload)
        if case == 'future': d['revision'] = 2
        if case == 'conflicting': d['jwks'] = {'keys': []}
        if case == 'expired': d.update(issuedAt=1, expiresAt=2)
        if case == 'wrong-audience': d['audience'] = 'attacker'
        payload, signature = bundle(d); paths[0].write_bytes(payload); paths[1].write_bytes(signature)
    if case == 'wrong-root':
        paths[2].write_bytes(ec.derive_private_key(18, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    if case == 'bad-signature': paths[1].write_bytes(b'\0' * 64)
    if case == 'missing-file': paths[0].unlink()
    if case == 'oversized-payload': paths[0].write_bytes(b'x' * (ingest.MAX_POLICY_BYTES + 1))
    if case == 'oversized-signature': paths[1].write_bytes(b'x' * 65)
    http = client(None if case == 'database' else engine, load_publication())
    unavailable(http.get(PUBLIC_POLICY_PATH))
    assert read_policy(engine) == before


def test_no_last_good_cache_and_atomic_operator_file_replacement(engine, tmp_path, monkeypatch):
    payload, signature, paths = configure(tmp_path, monkeypatch)
    installed(engine, (payload, signature))
    http = client(engine, load_publication())
    assert http.get(PUBLIC_POLICY_PATH).status_code == 200
    d = document(); d.update(revision=2, jwks={'keys': []})
    new_payload, new_signature = bundle(d)
    installed(engine, (new_payload, new_signature))
    unavailable(http.get(PUBLIC_POLICY_PATH, headers={'If-Modified-Since': 'Wed, 28 Oct 2026 00:00:00 GMT'}))
    # A mixed pair fails closed, then replacing both files makes the new policy visible.
    replacement = tmp_path / 'replacement'
    replacement.write_bytes(new_payload); replacement.replace(paths[0])
    unavailable(http.get(PUBLIC_POLICY_PATH))
    replacement.write_bytes(new_signature); replacement.replace(paths[1])
    response = http.get(PUBLIC_POLICY_PATH)
    assert response.status_code == 200
    assert json.loads(decode(response.json()['payload']))['jwks'] == {'keys': []}
    assert read_policy(engine).revision == 2


def test_route_rechecks_expiry_under_policy_lock(engine, tmp_path, monkeypatch):
    d = document(); d.update(issuedAt=999, expiresAt=1001)
    signed = bundle(d)
    monkeypatch.setattr(ingest, 'time', SimpleNamespace(time=lambda: 1000))
    configure(tmp_path, monkeypatch, signed); installed(engine, signed)
    clock = iter([1000, 1001])
    monkeypatch.setattr(ingest, 'time', SimpleNamespace(time=lambda: next(clock)))
    unavailable(client(engine, load_publication()).get(PUBLIC_POLICY_PATH))


def test_real_app_lifespan_loads_publication_and_restart_keeps_policy(engine, tmp_path, monkeypatch):
    from controlplane_api.config import settings
    signed = configure(tmp_path, monkeypatch)[:2]; installed(engine, signed)
    monkeypatch.setattr(settings, 'database_url', engine.url.render_as_string(hide_password=False))
    for _ in range(2):
        with TestClient(create_app(test_event_sink=[])) as http:
            response = http.get(PUBLIC_POLICY_PATH)
            assert response.status_code == 200
            assert decode(response.json()['payload']) == signed[0]


def test_reader_role_can_lock_but_cannot_modify_trust(engine, tmp_path, monkeypatch):
    signed = configure(tmp_path, monkeypatch)[:2]; installed(engine, signed)
    with engine.begin() as db:
        db.execute(text('CREATE ROLE witness_http_reader NOLOGIN NOBYPASSRLS'))
        db.execute(text('GRANT SELECT, UPDATE (id) ON sociacl_witness_policy TO witness_http_reader'))
    reader = create_engine(engine.url)
    @event.listens_for(reader, 'connect')
    def use_reader(connection, _):
        with connection.cursor() as cursor:
            cursor.execute('SET ROLE witness_http_reader')
        connection.commit()
    try:
        assert client(reader, load_publication()).get(PUBLIC_POLICY_PATH).status_code == 200
        for statement in ('UPDATE sociacl_witness_policy SET id = 2',
                          'UPDATE sociacl_witness_policy SET revision = 99',
                          "UPDATE sociacl_witness_policy SET jwks = '{\"keys\":[]}'",
                          "UPDATE sociacl_witness_policy SET history = '{}'",
                          'DELETE FROM sociacl_witness_policy',
                          'INSERT INTO sociacl_witness_policy(id) VALUES (1)'):
            with pytest.raises(DBAPIError):
                with reader.begin() as db: db.execute(text(statement))
        assert read_policy(engine).revision == 1
    finally:
        reader.dispose()
        with engine.begin() as db:
            db.execute(text('DROP OWNED BY witness_http_reader'))
            db.execute(text('DROP ROLE witness_http_reader'))


def test_root_is_pinned_until_application_restart(engine, tmp_path, monkeypatch):
    payload, signature, paths = configure(tmp_path, monkeypatch)
    installed(engine, (payload, signature))
    http = client(engine, load_publication())
    other = ec.derive_private_key(18, ec.SECP256R1())
    paths[2].write_bytes(other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    paths[1].write_bytes(sign(payload, other))
    unavailable(http.get(PUBLIC_POLICY_PATH))
    paths[1].write_bytes(signature)
    assert http.get(PUBLIC_POLICY_PATH).status_code == 200


def test_incomplete_configuration_stops_app_before_engines_start(monkeypatch):
    import importlib
    app_module = importlib.import_module('acl_service.app')
    for name in CONFIG_NAMES: monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(CONFIG_NAMES[3], AUDIENCE)
    monkeypatch.setattr(app_module, 'create_async_engine', lambda *a, **kw: pytest.fail('DB opened'))
    with pytest.raises(RuntimeError, match='^Invalid witness policy publication configuration$'):
        with TestClient(create_app(test_event_sink=[])):
            pytest.fail('startup succeeded')
