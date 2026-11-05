from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError

from acl_service.infrastructure.witness_checkpoint_replay import sign_refresh_once
from acl_service.infrastructure.witness_checkpoint_authorization import RefreshEnrollment
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_checkpoint_authorization import ENROLLMENT, BODY, HEADER, NOW
from test_witness_checkpoint_continuity import pinned  # noqa: F401
from test_witness_checkpoint import ready, engine, state_engine, state_url, verify_response  # noqa: F401


@pytest.fixture
def replay(ready):
    engine = ready['engine']
    with engine.begin() as db: db.execute(text('TRUNCATE sociacl_checkpoint_requests'))
    return engine


def issue(ready, config, replay, enrollment=ENROLLMENT, header=HEADER, **extra):
    return sign_refresh_once(enrollment, replay, BODY, header, config, ready['engine'],
        ready['policy_payload'], ready['policy_signature'], ready['policy_root'],
        management_private_key=ready['management_private_key'], clock=lambda:NOW, **extra)


def test_consumption_survives_reconnect(pinned, ready, replay):
    _, config, _ = pinned
    assert verify_response(issue(ready, config, replay))['client'] == ENROLLMENT.client
    replay.dispose()
    with pytest.raises(WitnessRejected): issue(ready, config, replay)


def test_concurrent_identical_requests_only_one_signs(pinned, ready, replay):
    _, config, _ = pinned
    barrier = Barrier(2)
    def attempt(_):
        barrier.wait(timeout=10)
        try: return issue(ready, config, replay)
        except WitnessRejected: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, range(2)))
    assert sum(result is not None for result in outcomes) == 1


def test_signing_failure_keeps_challenge_consumed(pinned, ready, replay):
    _, config, _ = pinned
    original = config.document_file.read_bytes()
    config.document_file.unlink()
    with pytest.raises(WitnessRejected): issue(ready, config, replay)
    config.document_file.write_bytes(original)
    with pytest.raises(WitnessRejected): issue(ready, config, replay)


def test_bad_authentication_does_not_consume(pinned, ready, replay):
    _, config, _ = pinned
    with pytest.raises(WitnessRejected): issue(ready, config, replay, header='bad')
    assert issue(ready, config, replay)


def test_renewed_credential_does_not_reset_replay(pinned, ready, replay):
    _, config, _ = pinned
    issue(ready, config, replay)
    with pytest.raises(WitnessRejected):
        issue(ready, config, replay, enrollment=replace(ENROLLMENT, expires_at=NOW+20))


def test_commit_failure_never_signs(pinned, ready, replay, monkeypatch):
    _, config, _ = pinned
    def fail(*args): raise OperationalError('commit', {}, Exception('private detail'))
    event.listen(replay, 'commit', fail)
    monkeypatch.setattr(RefreshEnrollment, 'sign_refresh', lambda *a, **k: pytest.fail('signed after failed commit'))
    try:
        with pytest.raises(WitnessRejected): issue(ready, config, replay)
    finally: event.remove(replay, 'commit', fail)


def test_database_only_retains_commitment_and_time(pinned, ready, replay):
    _, config, _ = pinned
    issue(ready, config, replay)
    with replay.connect() as db:
        row = db.execute(text('SELECT * FROM sociacl_checkpoint_requests')).mappings().one()
    assert set(row) == {'request_hash', 'consumed_at'}
    assert len(row['request_hash']) == 64 and row['consumed_at'] == NOW


def test_downgrade_cannot_erase_consumed_challenge(pinned, ready, replay):
    from pathlib import Path
    from alembic import command
    from sqlalchemy.exc import DBAPIError
    from controlplane_db import migrations
    _, config, _ = pinned
    issue(ready, config, replay)
    root = Path(migrations.__file__).with_name('migration_chains')
    with pytest.raises(DBAPIError, match='cannot discard checkpoint replay history'), replay.begin() as db:
        command.downgrade(migrations._config(root, 'platform', db), 'platform_0056_witness_policy')
    with pytest.raises(WitnessRejected): issue(ready, config, replay)


def test_new_challenge_can_follow_consumed_request(pinned, ready, replay):
    import json
    from test_witness_checkpoint_authorization import REQUEST
    _, config, _ = pinned
    issue(ready, config, replay)
    body = json.dumps(dict(REQUEST, challenge='A'*43)).encode()
    assert sign_refresh_once(ENROLLMENT, replay, body, HEADER, config, ready['engine'],
        ready['policy_payload'], ready['policy_signature'], ready['policy_root'],
        management_private_key=ready['management_private_key'], clock=lambda:NOW)


@pytest.mark.parametrize('timeout', [0, -1, 5001, True, 1.5, '1000', None])
def test_invalid_replay_timeout_rejected_before_database(pinned, ready, timeout):
    _, config, _ = pinned
    with pytest.raises(WitnessRejected):
        issue(ready, config, object(), replay_timeout_ms=timeout)


def test_locked_replay_table_times_out_without_signing(pinned, ready, replay, monkeypatch):
    _, config, _ = pinned
    with replay.connect() as db:
        previous = tuple(db.execute(text('SHOW ' + setting)).scalar_one()
                         for setting in ('lock_timeout', 'statement_timeout'))
    with monkeypatch.context() as patch:
        patch.setattr(RefreshEnrollment, 'sign_refresh',
                      lambda *a, **k: pytest.fail('signed after lock timeout'))
        with replay.begin() as blocker:
            blocker.execute(text('LOCK TABLE sociacl_checkpoint_requests IN ACCESS EXCLUSIVE MODE'))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(issue, ready, config, replay, replay_timeout_ms=50)
                with pytest.raises(WitnessRejected):
                    future.result(timeout=10)
    with replay.connect() as db:
        assert tuple(db.execute(text('SHOW ' + setting)).scalar_one()
                     for setting in ('lock_timeout', 'statement_timeout')) == previous
        assert db.execute(text('SELECT count(*) FROM sociacl_checkpoint_requests')).scalar_one() == 0
    assert issue(ready, config, replay)


def test_slow_replay_statement_times_out_without_signing(pinned, ready, replay, monkeypatch):
    _, config, _ = pinned
    def slow_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO sociacl_checkpoint_requests'):
            conn.exec_driver_sql('SELECT pg_sleep(1)')
    event.listen(replay, 'before_cursor_execute', slow_insert)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(RefreshEnrollment, 'sign_refresh',
                          lambda *a, **k: pytest.fail('signed after statement timeout'))
            with pytest.raises(WitnessRejected):
                issue(ready, config, replay, replay_timeout_ms=50)
    finally:
        event.remove(replay, 'before_cursor_execute', slow_insert)
    assert issue(ready, config, replay)
