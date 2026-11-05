"""Complete policy signing can consume a non-SQL storage interface."""
from contextlib import contextmanager
from copy import deepcopy

import pytest

from acl_service.domain.witness_policy_reader import PolicyHistorySnapshot
from acl_service.infrastructure import witness_checkpoint as issuer
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_checkpoint import FIXTURE, ROOT, MANAGEMENT, CHALLENGE, commitment, decode, verify_response


class MemoryHistoryReader:
    def __init__(self, row, after_enter=lambda: None, before_exit=lambda: None):
        self.row = row
        self.after_enter = after_enter
        self.before_exit = before_exit
        self.held = False

    @contextmanager
    def locked_history(self):
        self.held = True
        try:
            self.after_enter()
            yield deepcopy(self.row)
            self.before_exit()
        finally:
            self.held = False


@pytest.fixture
def inputs(monkeypatch):
    import json
    monkeypatch.setattr(ingest.time, 'time', lambda: FIXTURE['now'])
    state = deepcopy(FIXTURE['state'])
    envelope = json.loads(FIXTURE['policy'])
    reader = MemoryHistoryReader(PolicyHistorySnapshot(
        state['revision'], state['jwks'], {e['jwk']['kid']: e for e in state['history']},
    ))
    return dict(policy_reader=reader, policy_payload=decode(envelope['payload']),
                policy_signature=decode(envelope['signature']), policy_root=ROOT,
                audience=state['audience'], management_private_key=MANAGEMENT,
                continuity=issuer.CheckpointContinuity(1, commitment(state)),
                client='client-enrollment-1', challenge=CHALLENGE,
                clock=lambda: FIXTURE['now'])


def test_checkpoint_signs_inside_history_lease(inputs, monkeypatch):
    reader = inputs['policy_reader']
    original = issuer._sign_payload
    def sign(*args):
        assert reader.held
        return original(*args)
    monkeypatch.setattr(issuer, '_sign_payload', sign)
    result = verify_response(issuer.sign_checkpoint_for_verified_refresh(**inputs))
    assert result['state'] == FIXTURE['state']
    assert not reader.held


@pytest.mark.parametrize('case', ['absent', 'incomplete', 'changed'])
def test_bad_history_cannot_produce_checkpoint(inputs, case):
    reader = inputs['policy_reader']
    if case == 'absent':
        reader.row = None
    elif case == 'incomplete':
        reader.row.history.clear()
    else:
        reader.row = PolicyHistorySnapshot(reader.row.revision + 1, reader.row.jwks, reader.row.history)
    with pytest.raises(WitnessRejected):
        issuer.sign_checkpoint_for_verified_refresh(**inputs)
    assert not reader.held


def test_exit_failure_cannot_release_signed_response(inputs):
    def fail():
        raise RuntimeError('storage exit failed')
    inputs['policy_reader'].before_exit = fail
    with pytest.raises(RuntimeError, match='storage exit failed'):
        issuer.sign_checkpoint_for_verified_refresh(**inputs)
    assert not inputs['policy_reader'].held


def test_expiry_after_signing_discards_response(inputs, monkeypatch):
    original = issuer._sign_payload
    def sign(*args):
        result = original(*args)
        monkeypatch.setattr(ingest.time, 'time', lambda: FIXTURE['now'] + 1000)
        return result
    monkeypatch.setattr(issuer, '_sign_payload', sign)
    with pytest.raises(WitnessRejected):
        issuer.sign_checkpoint_for_verified_refresh(**inputs)
    assert not inputs['policy_reader'].held
