"""Backend-independent signing/replay ordering and failure boundaries."""
from contextlib import contextmanager
from types import SimpleNamespace
import time

import pytest

from acl_service.domain.witness_policy_reader import PolicySnapshot
from acl_service.infrastructure.witness_policy_signing import sign_with_policy
from acl_service.infrastructure.witness_checkpoint_replay import sign_refresh_once
from acl_service.infrastructure.witness_checkpoint_authorization import RefreshEnrollment
from acl_service.infrastructure.witness_signer import WitnessRejected, WitnessSigner
from test_witness_policy_repo import key
from test_witness_checkpoint_authorization import ENROLLMENT, BODY, HEADER, NOW


class Reader:
    def __init__(self, snapshot, fail_exit=False):
        self.snapshot = snapshot
        self.fail_exit = fail_exit
        self.held = False

    @contextmanager
    def locked_policy(self):
        self.held = True
        try:
            yield self.snapshot
            if self.fail_exit:
                raise RuntimeError('uncertain storage exit')
        finally:
            self.held = False


@pytest.mark.parametrize('fail_exit', [False, True])
def test_timestamp_signs_under_lease_and_returns_only_after_exit(monkeypatch, fail_exit):
    witness, private = key()
    reader = Reader(PolicySnapshot(1, {'keys': [witness.jwk()]}), fail_exit)
    original = WitnessSigner.sign_verified
    def sign(self, *args, **kwargs):
        assert reader.held
        return original(self, *args, **kwargs)
    monkeypatch.setattr(WitnessSigner, 'sign_verified', sign)
    if fail_exit:
        with pytest.raises(RuntimeError):
            sign_with_policy(reader, witness.kid, private, {'typ': 'test'}, issued_at=int(time.time()))
    else:
        assert sign_with_policy(reader, witness.kid, private, {'typ': 'test'},
                                issued_at=int(time.time())).count('.') == 2
    assert not reader.held


class Replay:
    def __init__(self, fail=False):
        self.seen = set()
        self.fail = fail

    def consume(self, request_hash, consumed_at, *, timeout_ms):
        assert consumed_at == NOW and timeout_ms == 1000
        if self.fail or request_hash in self.seen:
            raise WitnessRejected()
        self.seen.add(request_hash)


def refresh(store, header=HEADER, clock=lambda: NOW):
    return sign_refresh_once(ENROLLMENT, store, BODY, header,
        SimpleNamespace(root_epoch=ENROLLMENT.root_epoch), object(), b'', b'', object(),
        management_private_key=object(), clock=clock)


def test_replay_commits_before_signing_and_no_retry_after_failed_sign(monkeypatch):
    store = Replay()
    def fail(*args, **kwargs):
        assert len(store.seen) == 1
        raise RuntimeError('signing failed')
    monkeypatch.setattr(RefreshEnrollment, 'sign_refresh', fail)
    with pytest.raises(RuntimeError):
        refresh(store)
    with pytest.raises(WitnessRejected):
        refresh(store)


@pytest.mark.parametrize('case', ['auth', 'commit'])
def test_replay_authentication_and_commit_failure_never_sign(monkeypatch, case):
    store = Replay(fail=case == 'commit')
    monkeypatch.setattr(RefreshEnrollment, 'sign_refresh',
                        lambda *a, **kw: pytest.fail('signed without committed consumption'))
    with pytest.raises(WitnessRejected):
        refresh(store, header='bad' if case == 'auth' else HEADER)
    assert not store.seen


def test_replay_commit_wait_is_part_of_freshness(monkeypatch):
    store = Replay()
    samples = iter([NOW, ENROLLMENT.expires_at])
    def sign(*args, **kwargs):
        kwargs['clock']()
        pytest.fail('expired consumption reached signing')
    monkeypatch.setattr(RefreshEnrollment, 'sign_refresh', sign)
    with pytest.raises(WitnessRejected):
        refresh(store, clock=lambda: next(samples))
    assert len(store.seen) == 1
