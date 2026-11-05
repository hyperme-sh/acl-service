import base64
import json

import pytest

from acl_service.infrastructure.witness_policy_repo import PostgresWitnessPolicyWriter
from acl_service.infrastructure.witness_policy_repo import PostgresWitnessPolicyReader
from acl_service import witness_policy_cli as cli
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_policy_export import export_signed_policy
from acl_service.infrastructure.witness_policy_repo import read_policy
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_policy_ingest import ROOT_KEY, AUDIENCE, bundle, document, files, sign
from test_witness_policy_repo import engine, key  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401


def export(engine, payload, signature):
    return export_signed_policy(PostgresWitnessPolicyReader(engine), payload, signature, ROOT_KEY.public_key(), AUDIENCE)


def install(engine, payload, signature):
    return ingest.install_signed_policy(PostgresWitnessPolicyWriter(engine), payload, signature, ROOT_KEY.public_key(), AUDIENCE)


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def test_export_preserves_exact_signed_bytes_and_state(engine):
    d = document()
    d['jwks']['keys'].append(key(kid='second', scalar=8)[0].jwk())
    payload = json.dumps(d, indent=2).encode() + b'\n'
    signature = sign(payload)
    install(engine, payload, signature)
    before = read_policy(engine)
    result = export(engine, payload, signature)
    assert set(result) == {'type', 'payload', 'signature'}
    assert result['type'] == 'sociacl-witness-policy-envelope-v1'
    assert decode(result['payload']) == payload
    assert decode(result['signature']) == signature
    assert '=' not in result['payload'] + result['signature']
    assert ingest.verify_policy(decode(result['payload']), decode(result['signature']),
                                ROOT_KEY.public_key(), AUDIENCE).revision == 1
    assert read_policy(engine) == before


@pytest.mark.parametrize('case', ['absent', 'older', 'future', 'conflicting'])
def test_uninstalled_policy_cannot_be_exported(engine, case):
    d = document()
    payload, signature = bundle(d)
    if case != 'absent':
        install(engine, payload, signature)
    if case == 'older':
        newer = {**d, 'revision': 2, 'jwks': {'keys': []}}
        install(engine, *bundle(newer))
    elif case == 'future':
        payload, signature = bundle({**d, 'revision': 2})
    elif case == 'conflicting':
        payload, signature = bundle({**d, 'jwks': {'keys': []}})
    before = read_policy(engine)
    with pytest.raises(WitnessRejected):
        export(engine, payload, signature)
    assert read_policy(engine) == before


def test_empty_removal_policy_exports_but_removed_bundle_does_not(engine):
    old = bundle()
    install(engine, *old)
    d = document(); d.update(revision=2, jwks={'keys': []})
    current = bundle(d)
    install(engine, *current)
    assert decode(export(engine, *current)['payload']) == current[0]
    with pytest.raises(WitnessRejected):
        export(engine, *old)


def test_export_rechecks_expiry_after_acquiring_policy_lock(engine, monkeypatch):
    d = document(); d.update(issuedAt=999, expiresAt=1001)
    monkeypatch.setattr(ingest.time, 'time', lambda: 1000)
    signed = bundle(d)
    install(engine, *signed)
    samples = iter([1000, 1001])
    monkeypatch.setattr(ingest.time, 'time', lambda: next(samples))
    with pytest.raises(WitnessRejected):
        export(engine, *signed)
    assert read_policy(engine).revision == 1


def test_cli_export_requires_installed_policy_and_preserves_bytes(engine, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('DATABASE_URL', engine.url.render_as_string(hide_password=False))
    payload, signature = bundle()
    args = files(tmp_path, payload, signature) + ['--export']
    assert cli.main(args) == 1
    assert capsys.readouterr().out == 'witness policy rejected\n'
    assert read_policy(engine) is None
    install(engine, payload, signature)
    assert cli.main(args) == 0
    assert decode(json.loads(capsys.readouterr().out)['payload']) == payload
    with pytest.raises(SystemExit):
        cli.main(args + ['--check'])


def test_invalid_export_never_connects(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('invalid signature must fail before database access')
    monkeypatch.setattr(cli, 'create_engine', forbidden)
    payload, signature = bundle()
    assert cli.main(files(tmp_path, payload + b' ', signature) + ['--export']) == 1
    assert capsys.readouterr().out == 'witness policy rejected\n'


def test_reader_lease_blocks_updates_and_detaches_snapshot(engine):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    signed = bundle()
    install(engine, *signed)
    reader = PostgresWitnessPolicyReader(engine)
    with reader.locked_policy() as snapshot:
        snapshot.jwks['keys'].clear()
        # A distinct connection cannot obtain a conflicting write lock while
        # the read lease is active. NOWAIT makes this independent of scheduling.
        with pytest.raises(DBAPIError) as failure:
            with engine.begin() as connection:
                connection.execute(text(
                    'SELECT id FROM sociacl_witness_policy WHERE id = 1 FOR UPDATE NOWAIT'
                ))
        assert failure.value.orig.sqlstate == '55P03'
    assert read_policy(engine).jwks['keys']
    with engine.begin() as connection:
        assert connection.execute(text(
            'SELECT id FROM sociacl_witness_policy WHERE id = 1 FOR UPDATE NOWAIT'
        )).scalar_one() == 1


def test_reader_lease_releases_lock_when_export_fails(engine):
    from sqlalchemy import text

    install(engine, *bundle())
    with pytest.raises(WitnessRejected):
        export(engine, *bundle({**document(), 'revision': 2}))
    with engine.begin() as connection:
        assert connection.execute(text(
            'SELECT id FROM sociacl_witness_policy WHERE id = 1 FOR UPDATE NOWAIT'
        )).scalar_one() == 1
