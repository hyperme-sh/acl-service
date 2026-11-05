"""PostgreSQL lifecycle tests; input policy authentication remains external."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import event, text

from acl_service.infrastructure.witness_signer import WitnessKey, WitnessRejected
from acl_service.infrastructure.witness_policy_repo import (
    PostgresWitnessPolicyWriter, PostgresWitnessSigningPolicyReader, read_policy,
)
from controlplane_db import migrations
from test_keyring_state_repo import state_url, state_engine  # noqa: F401


def sign_with_policy(engine, *args, **kwargs):
    from acl_service.infrastructure.witness_policy_signing import sign_with_policy as sign
    return sign(PostgresWitnessSigningPolicyReader(engine), *args, **kwargs)


def install(engine, revision, keys):
    return PostgresWitnessPolicyWriter(engine).install_verified(
        revision, keys, check_authorization=lambda: None,
    )


@pytest.fixture
def engine(state_engine):
    with state_engine.begin() as db:
        db.execute(text("TRUNCATE sociacl_witness_policy"))
    return state_engine


def key(kid="first", scalar=7):
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    now = int(time.time())
    return WitnessKey(kid, now - 100, now + 1000, private.public_key()), private


def test_revision_and_removed_keys_survive_reconnect(engine):
    first, _ = key()
    assert read_policy(engine) is None
    install(engine, 1, [first])
    removed = install(engine, 2, [])
    engine.dispose()
    assert read_policy(engine) == removed
    for revision, keys in [(1, [first]), (2, [first]), (3, [first]),
                           (3, [replace(first, kid="renamed")])]:
        with pytest.raises(WitnessRejected):
            install(engine, revision, keys)
        assert read_policy(engine) == removed
    other, _ = key("new", 8)
    assert install(engine, 3, [other]).revision == 3


def test_retries_are_idempotent_and_windows_only_narrow(engine):
    first, _ = key()
    second, _ = key("second", 8)
    original = install(engine, 1, [second, first])
    assert install(engine, 1, [first, second]) == original
    narrowed = replace(first, not_before=first.not_before + 1, not_after=first.not_after - 1)
    current = install(engine, 2, [narrowed, second])
    for keys in [[first, second], [replace(narrowed, not_before=first.not_before), second],
                 [replace(narrowed, public_key=key("third", 9)[0].public_key), second]]:
        with pytest.raises(WitnessRejected):
            install(engine, 3, keys)
        assert read_policy(engine) == current
    current.jwks["keys"].clear()
    assert len(read_policy(engine).jwks["keys"]) == 2


def test_concurrent_same_revision_has_only_one_winner(engine):
    barrier = Barrier(2)
    keys = [key("a", 7)[0], key("b", 8)[0]]
    def write(candidate):
        barrier.wait(timeout=10)
        try:
            return install(engine, 1, [candidate])
        except WitnessRejected:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, keys))
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    assert read_policy(engine) == winners[0]


def test_failure_rolls_back_revision_document_and_tombstones(engine):
    first, _ = key()
    original = install(engine, 1, [first])
    def fail(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE sociacl_witness_policy"):
            raise RuntimeError("injected failure after UPDATE")
    event.listen(engine, "after_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError):
            install(engine, 2, [])
    finally:
        event.remove(engine, "after_cursor_execute", fail)
    engine.dispose()
    assert read_policy(engine) == original
    assert install(engine, 2, [first]).revision == 2


def test_signing_uses_current_policy_and_refuses_removed_or_shortened_key(engine):
    first, private = key()
    issued = int(time.time())
    with pytest.raises(WitnessRejected):
        sign_with_policy(engine, first.kid, private, {"typ": "test"}, issued_at=issued)
    install(engine, 1, [first])
    assert sign_with_policy(engine, first.kid, private, {"typ": "test"}, issued_at=issued).count(".") == 2
    install(engine, 2, [replace(first, not_after=issued)])
    with pytest.raises(WitnessRejected):
        sign_with_policy(engine, first.kid, private, {"typ": "test"}, issued_at=issued - 1)
    install(engine, 3, [])
    with pytest.raises(WitnessRejected):
        sign_with_policy(engine, first.kid, private, {"typ": "test"}, issued_at=issued)


@pytest.mark.parametrize("revision", [0, -1, True, 1.5, 9007199254740992])
def test_invalid_revision_does_not_create_state(engine, revision):
    with pytest.raises(WitnessRejected):
        install(engine, revision, [])
    assert read_policy(engine) is None


def test_downgrade_refuses_even_an_empty_trusted_policy(engine):
    install(engine, 1, [])
    from pathlib import Path
    from alembic import command
    from sqlalchemy.exc import DBAPIError
    root = Path(migrations.__file__).with_name("migration_chains")
    with pytest.raises(DBAPIError, match="cannot discard SociACL witness policy history"), engine.begin() as db:
        command.downgrade(migrations._config(root, "platform", db), "platform_0055_sociacl_keyring")


def test_policy_removal_waits_for_in_flight_signing(engine, monkeypatch):
    from concurrent.futures import TimeoutError
    from threading import Event
    from acl_service.infrastructure import witness_policy_signing as repo
    first, private = key()
    install(engine, 1, [first])
    signing, release, update_started = Event(), Event(), Event()
    original = repo.WitnessSigner.sign_verified
    def held_sign(self, *args, **kwargs):
        signing.set()
        assert release.wait(timeout=10)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(repo.WitnessSigner, "sign_verified", held_sign)
    def started(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO sociacl_witness_policy"):
            update_started.set()
    event.listen(engine, "before_cursor_execute", started)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            signing_result = pool.submit(sign_with_policy, engine, first.kid, private,
                                         {"typ": "test"}, issued_at=int(time.time()))
            assert signing.wait(timeout=10)
            removal = pool.submit(install, engine, 2, [])
            try:
                assert update_started.wait(timeout=10)
                with pytest.raises(TimeoutError):
                    removal.result(timeout=0.2)
            finally:
                release.set()
            assert signing_result.result(timeout=10).count(".") == 2
            assert removal.result(timeout=10).revision == 2
    finally:
        release.set()
        event.remove(engine, "before_cursor_execute", started)
    with pytest.raises(WitnessRejected):
        sign_with_policy(engine, first.kid, private, {"typ": "test"}, issued_at=int(time.time()))
