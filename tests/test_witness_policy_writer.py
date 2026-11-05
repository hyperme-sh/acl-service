"""Signed ingestion authenticates before invoking a replaceable writer."""
from copy import deepcopy

import pytest

from acl_service.domain.witness_policy_reader import PolicySnapshot
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_policy_repo import PostgresWitnessPolicyWriter, read_policy
from acl_service.infrastructure.witness_signer import WitnessRejected, public_jwks
from test_witness_policy_ingest import ROOT_KEY, AUDIENCE, bundle, document
from test_witness_policy_repo import engine  # noqa: F401
from test_keyring_state_repo import state_url, state_engine  # noqa: F401


class RecordingWriter:
    def __init__(self, before_check=lambda: None):
        self.calls = 0
        self.committed = None
        self.before_check = before_check

    def install_verified(self, revision, keys, *, check_authorization):
        self.calls += 1
        self.before_check()
        check_authorization()
        self.committed = PolicySnapshot(revision, public_jwks(keys))
        return deepcopy(self.committed)


def install(writer, signed, audience=AUDIENCE):
    return ingest.install_signed_policy(writer, *signed, ROOT_KEY.public_key(), audience)


def test_signed_install_works_without_database():
    writer = RecordingWriter()
    result = install(writer, bundle())
    assert writer.calls == 1 and result.revision == 1
    result.jwks['keys'].clear()
    assert writer.committed.jwks['keys']


@pytest.mark.parametrize('case', ['signature', 'audience', 'expiry'])
def test_unauthenticated_update_never_reaches_writer(case):
    signed = bundle()
    audience = AUDIENCE
    if case == 'signature':
        signed = signed[0], b'\x00' * 64
    elif case == 'audience':
        audience = 'another-deployment'
    else:
        signed = bundle({**document(), 'issuedAt': 1, 'expiresAt': 2})
    writer = RecordingWriter()
    with pytest.raises(WitnessRejected):
        install(writer, signed, audience)
    assert writer.calls == 0 and writer.committed is None


def test_waiting_for_writer_rechecks_expiry(monkeypatch):
    monkeypatch.setattr(ingest.time, 'time', lambda: 1000)
    signed = bundle({**document(), 'issuedAt': 999, 'expiresAt': 1001})
    writer = RecordingWriter(lambda: monkeypatch.setattr(ingest.time, 'time', lambda: 1001))
    with pytest.raises(WitnessRejected):
        install(writer, signed)
    assert writer.calls == 1 and writer.committed is None


def test_postgres_retry_rechecks_authorization_and_preserves_policy(engine, monkeypatch):
    monkeypatch.setattr(ingest.time, 'time', lambda: 1000)
    signed = bundle({**document(), 'issuedAt': 999, 'expiresAt': 1001})
    writer = PostgresWitnessPolicyWriter(engine)
    before = install(writer, signed)
    samples = iter([1000, 1001])
    monkeypatch.setattr(ingest.time, 'time', lambda: next(samples))
    with pytest.raises(WitnessRejected):
        install(writer, signed)
    assert read_policy(engine) == before
