"""PostgreSQL acceptance for the storage primitive; no crypto authorization claim."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine, event, text

from acl_service.infrastructure.keyring_state_repo import (
    MAX_GENERATION, StoreRejected, compare_and_swap_verified as cas,
    observe_verified_head, read_state,
)
from controlplane_db import migrations

P = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"


@pytest.fixture(scope="module")
def state_url(require_docker):
    from testcontainers.postgres import PostgresContainer
    with PostgresContainer("postgres:17@sha256:3b0cda93be7c8dba2ed484d19393d93845dc3dafb88973e248ba8e6d99d784e1", driver="psycopg") as pg:
        yield pg.get_connection_url()


@pytest.fixture
def state_engine(state_url):
    engine = create_engine(state_url)
    with engine.begin() as db:
        db.execute(text("""DO $$ BEGIN CREATE ROLE controlplane;
            EXCEPTION WHEN duplicate_object THEN NULL; END $$"""))
        db.execute(text("""DO $$ BEGIN CREATE ROLE controlplane_app NOBYPASSRLS;
            EXCEPTION WHEN duplicate_object THEN NULL; END $$"""))
    migrations.upgrade(state_url, chains=["platform"])
    with engine.begin() as db:
        db.execute(text("TRUNCATE sociacl_keyring_state"))
    yield engine
    engine.dispose()


def test_floor_and_generations_survive_reconnect_and_empty_payload(state_engine):
    engine = state_engine
    assert read_state(engine, P) is None
    cas(engine, P, head=2, kind="recovery", expected_generation=0, payload=b"ciphertext")
    cas(engine, P, head=3, kind="wraps", expected_generation=0, payload=b"wraps")
    cas(engine, P, head=3, kind="recovery", expected_generation=1, payload=b"")
    engine.dispose()
    snapshot = read_state(engine, P)
    assert (snapshot.head_floor, snapshot.recovery_generation, snapshot.wrap_generation) == (3, 2, 1)
    assert (snapshot.recovery, snapshot.wraps) == (b"", b"wraps")
    with pytest.raises(StoreRejected):
        cas(engine, P, head=3, kind="recovery", expected_generation=0, payload=b"replay")
    with pytest.raises(StoreRejected):
        observe_verified_head(engine, P, 2)
    assert read_state(engine, P) == snapshot


def test_rejected_write_keeps_verified_floor_and_all_ciphertext(state_engine):
    cas(state_engine, P, head=1, kind="recovery", expected_generation=0, payload=b"old")
    with pytest.raises(StoreRejected):
        cas(state_engine, P, head=4, kind="wraps", expected_generation=7, payload=b"bad")
    state_engine.dispose()
    state = read_state(state_engine, P)
    assert (state.head_floor, state.recovery, state.wraps) == (4, b"old", b"")
    assert (state.recovery_generation, state.wrap_generation) == (1, 0)
    with pytest.raises(StoreRejected):
        cas(state_engine, P, head=3, kind="recovery", expected_generation=1, payload=b"rollback")


def test_concurrent_first_writers_have_one_winner(state_engine):
    barrier = Barrier(2)
    def write(payload):
        barrier.wait(timeout=10)
        try:
            return cas(state_engine, P, head=1, kind="recovery", expected_generation=0, payload=payload)
        except StoreRejected:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, [b"one", b"two"]))
    assert sum(row is not None for row in results) == 1
    state = read_state(state_engine, P)
    assert state.recovery_generation == 1
    assert state.recovery in (b"one", b"two")
    # A caller may submit a freshly authorized transition at the reread generation.
    assert cas(state_engine, P, head=1, kind="recovery", expected_generation=state.recovery_generation, payload=b"new").recovery_generation == 2


def test_failure_after_sql_update_rolls_back_payload_floor_and_generation(state_engine):
    before = cas(state_engine, P, head=1, kind="recovery", expected_generation=0, payload=b"old")
    def fail_after_update(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE sociacl_keyring_state"):
            raise RuntimeError("injected failure before commit")
    event.listen(state_engine, "after_cursor_execute", fail_after_update)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            cas(state_engine, P, head=2, kind="recovery", expected_generation=1, payload=b"new")
    finally:
        event.remove(state_engine, "after_cursor_execute", fail_after_update)
    state_engine.dispose()
    assert read_state(state_engine, P) == before


def test_generation_exhaustion_keeps_state_readable(state_engine):
    observe_verified_head(state_engine, P, 0)
    with state_engine.begin() as db:
        db.execute(text("UPDATE sociacl_keyring_state SET recovery_generation=:generation WHERE principal=:principal"), {"generation": MAX_GENERATION - 1, "principal": P})
    last = cas(state_engine, P, head=0, kind="recovery", expected_generation=MAX_GENERATION - 1, payload=b"last")
    with pytest.raises(StoreRejected):
        cas(state_engine, P, head=0, kind="recovery", expected_generation=MAX_GENERATION, payload=b"overflow")
    assert read_state(state_engine, P) == last
    # Independent wrap generation still progresses with the same shared floor.
    assert cas(state_engine, P, head=0, kind="wraps", expected_generation=0, payload=b"wrap").wrap_generation == 1


def test_both_stores_share_lock_without_lost_updates(state_engine):
    barrier = Barrier(2)
    def write(kind):
        barrier.wait(timeout=10)
        return cas(state_engine, P, head=2, kind=kind, expected_generation=0, payload=kind.encode())
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(write, ["recovery", "wraps"]))
    state = read_state(state_engine, P)
    assert (state.recovery, state.wraps) == (b"recovery", b"wraps")
    assert (state.head_floor, state.recovery_generation, state.wrap_generation) == (2, 1, 1)


def test_committed_state_survives_database_restart(require_docker):
    from acl_service.infrastructure.witness_policy_repo import install_verified_policy, read_policy
    from acl_service.infrastructure.witness_signer import WitnessKey, WitnessRejected
    from cryptography.hazmat.primitives.asymmetric import ec
    import time
    from sqlalchemy.exc import OperationalError
    from testcontainers.postgres import PostgresContainer
    # A dedicated container avoids invalidating another test's cached host port.
    with PostgresContainer("postgres:17@sha256:3b0cda93be7c8dba2ed484d19393d93845dc3dafb88973e248ba8e6d99d784e1", driver="psycopg") as pg:
        engine = create_engine(pg.get_connection_url())
        with engine.begin() as db:
            db.execute(text("CREATE ROLE controlplane; CREATE ROLE controlplane_app NOBYPASSRLS"))
        migrations.upgrade(str(engine.url.render_as_string(hide_password=False)), chains=["platform"])
        before = cas(engine, P, head=7, kind="recovery", expected_generation=0, payload=b"durable")
        retired = WitnessKey("restart-test", 1000, 2000, ec.derive_private_key(7, ec.SECP256R1()).public_key())
        install_verified_policy(engine, 1, [retired])
        policy = install_verified_policy(engine, 2, [])
        engine.dispose()
        pg.get_wrapped_container().restart(timeout=5)
        # Docker may allocate a different published port on restart.
        pg.get_wrapped_container().reload()
        engine = create_engine(pg.get_connection_url())
        deadline = time.monotonic() + 20
        try:
            while True:
                try:
                    assert read_state(engine, P) == before
                    assert read_policy(engine) == policy
                    with pytest.raises(WitnessRejected):
                        install_verified_policy(engine, 3, [retired])
                    break
                except OperationalError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
        finally:
            engine.dispose()


def test_migration_refuses_downgrade_with_even_empty_state(state_engine):
    from pathlib import Path
    from alembic import command
    from sqlalchemy.exc import DBAPIError
    observe_verified_head(state_engine, P, 4)
    root = Path(migrations.__file__).with_name("migration_chains")
    with pytest.raises(DBAPIError, match="cannot discard SociACL"), state_engine.begin() as db:
        command.downgrade(migrations._config(root, "platform", db), "platform_0054_subject_scope")
    assert read_state(state_engine, P).head_floor == 4


@pytest.mark.parametrize("value", [-1, MAX_GENERATION + 1, True, 1.5])
def test_invalid_verified_head_does_not_create_state(state_engine, value):
    with pytest.raises(StoreRejected):
        observe_verified_head(state_engine, P, value)
    assert read_state(state_engine, P) is None
