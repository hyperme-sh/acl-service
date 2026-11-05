"""Independent pin authentication, withdrawal and bounded issuance."""
import hashlib
import json
from dataclasses import replace

import pytest

from acl_service.infrastructure import witness_checkpoint_continuity as source
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_checkpoint import ready, engine, state_url, state_engine, FIXTURE, verify_response  # noqa: F401


@pytest.fixture
def pinned(tmp_path, ready):
    doc = dict(type='sociacl-witness-continuity-v1', audience=ready['audience'],
               root=source._public(ready['policy_root']),
               managementRoot=source._public(ready['management_private_key'].public_key()),
               rootEpoch=1, stateSha256=ready['continuity'].state_sha256.hex(),
               issuedAt=FIXTURE['now'], expiresAt=FIXTURE['now'] + 30)
    path = tmp_path / 'continuity.json'
    def save(document):
        raw = json.dumps(document).encode()
        path.write_bytes(raw)
        return source.PinnedCheckpointContinuity(path, hashlib.sha256(raw).digest(), 1)
    return doc, save(doc), save


def sign(pinned, ready, **changes):
    args = {k: v for k, v in ready.items() if k != 'continuity'}
    args.update(clock=lambda: FIXTURE['now'], **changes)
    return pinned.sign_for_verified_refresh(**args)


def test_pinned_source_bounds_response_lease(pinned, ready):
    doc, config, _ = pinned
    assert verify_response(sign(config, ready))['expiresAt'] == doc['expiresAt']


@pytest.mark.parametrize('field,value', [
    ('type', 'other'), ('audience', 'other'), ('root', 'other'), ('managementRoot', 'other'),
    ('rootEpoch', 2), ('rootEpoch', True), ('stateSha256', 'x'*64),
    ('issuedAt', True), ('issuedAt', FIXTURE['now'] + 1),
    ('expiresAt', FIXTURE['now']), ('expiresAt', FIXTURE['now'] + 86401),
    ('extra', 1),
])
def test_even_pinned_invalid_documents_fail_before_database(pinned, ready, field, value):
    doc, _, save = pinned
    doc[field] = value
    ready['policy_reader'] = object()
    with pytest.raises(WitnessRejected): sign(save(doc), ready)


def test_changed_or_missing_file_never_uses_cached_continuity(pinned, ready):
    _, config, _ = pinned
    sign(config, ready)
    config.document_file.write_bytes(b'{}')
    with pytest.raises(WitnessRejected): sign(config, ready)
    config.document_file.unlink()
    with pytest.raises(WitnessRejected): sign(config, ready)


def test_old_document_rejected_by_new_independent_pin(pinned, ready):
    doc, old, save = pinned
    old_bytes = old.document_file.read_bytes()
    doc['expiresAt'] += 1
    new = save(doc)
    new.document_file.write_bytes(old_bytes)
    with pytest.raises(WitnessRejected): sign(new, ready)


@pytest.mark.parametrize('raw', [b'{', b'[]', b'\xff', b'{"type":1,"type":2}', b'x'*8193])
def test_malformed_exactly_pinned_bytes(pinned, ready, raw):
    _, config, _ = pinned
    config.document_file.write_bytes(raw)
    config = replace(config, document_sha256=hashlib.sha256(raw).digest())
    with pytest.raises(WitnessRejected): sign(config, ready)


@pytest.mark.parametrize('change', ['withdraw', 'expire', 'monotonic'])
def test_source_withdrawal_and_expiry_during_signing(pinned, ready, monkeypatch, change):
    _, config, _ = pinned
    original = source.issuer._sign_payload
    now = [FIXTURE['now']]
    elapsed = [0]
    def delayed(*args):
        result = original(*args)
        if change == 'withdraw': config.document_file.unlink()
        if change == 'expire': now[0] += 30
        if change == 'monotonic': elapsed[0] += 30
        return result
    monkeypatch.setattr(source.issuer, '_sign_payload', delayed)
    args = {k: v for k, v in ready.items() if k != 'continuity'}
    with pytest.raises(WitnessRejected):
        config.sign_for_verified_refresh(**args, clock=lambda: now[0], monotonic=lambda: elapsed[0])


def test_pinned_wrong_history_cannot_authorize_database(pinned, ready):
    doc, _, save = pinned
    doc['stateSha256'] = '0'*64
    with pytest.raises(WitnessRejected): sign(save(doc), ready)


@pytest.mark.parametrize('changes', [dict(root_epoch=True), dict(root_epoch=0),
    dict(document_sha256=b'x'), dict(document_file='relative')])
def test_invalid_trusted_configuration(pinned, ready, changes):
    _, config, _ = pinned
    with pytest.raises(WitnessRejected): sign(replace(config, **changes), ready)


def test_final_file_read_is_inside_deadline(pinned, ready, monkeypatch):
    _, config, _ = pinned
    original = source.read_regular_file
    calls = [0]
    now = [FIXTURE['now']]
    def slow_read(*args):
        raw = original(*args)
        calls[0] += 1
        if calls[0] == 2: now[0] += 30
        return raw
    monkeypatch.setattr(source, 'read_regular_file', slow_read)
    args = {k: v for k, v in ready.items() if k != 'continuity'}
    with pytest.raises(WitnessRejected):
        config.sign_for_verified_refresh(**args, clock=lambda: now[0])


def test_delay_before_signer_does_not_extend_source_lease(pinned, ready, monkeypatch):
    _, config, _ = pinned
    original = source.issuer.sign_checkpoint_for_verified_refresh
    now = [FIXTURE['now']]
    def delayed(*args, **kwargs):
        now[0] += 20
        return original(*args, **kwargs)
    monkeypatch.setattr(source.issuer, 'sign_checkpoint_for_verified_refresh', delayed)
    args = {k: v for k, v in ready.items() if k != 'continuity'}
    result = verify_response(config.sign_for_verified_refresh(**args, clock=lambda: now[0]))
    assert result['issuedAt'] == FIXTURE['now'] + 20
    assert result['expiresAt'] == FIXTURE['now'] + 30


@pytest.mark.parametrize('lease', ['request', 'policy'])
@pytest.mark.parametrize('clock_kind', ['utc', 'monotonic'])
def test_final_read_cannot_outlive_shorter_checkpoint(pinned, ready, monkeypatch, lease, clock_kind):
    doc, config, save = pinned
    # The policy fixture expires in 120s; make the source longer than that.
    doc['expiresAt'] = FIXTURE['now'] + 300
    config = save(doc)
    now, elapsed, calls = [FIXTURE['now']], [0], [0]
    original = source.read_regular_file
    def slow_read(*args):
        raw = original(*args)
        calls[0] += 1
        if calls[0] == 2:
            delay = 2 if lease == 'request' else 120
            if clock_kind == 'utc': now[0] += delay
            else: elapsed[0] += delay
        return raw
    monkeypatch.setattr(source, 'read_regular_file', slow_read)
    args = {k: v for k, v in ready.items() if k != 'continuity'}
    with pytest.raises(WitnessRejected):
        config.sign_for_verified_refresh(**args, lifetime=1 if lease == 'request' else 300,
            clock=lambda: now[0], monotonic=lambda: elapsed[0])
    assert calls[0] == 2
