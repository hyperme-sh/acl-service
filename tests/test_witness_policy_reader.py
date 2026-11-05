"""Export contract works without a database and revalidates within the lease."""
from contextlib import contextmanager
from copy import deepcopy

import pytest

from acl_service.domain.witness_policy_reader import PolicySnapshot
from acl_service.infrastructure import witness_policy_ingest as ingest
from acl_service.infrastructure.witness_policy_export import export_signed_policy
from acl_service.infrastructure.witness_signer import WitnessRejected
from test_witness_policy_ingest import AUDIENCE, ROOT_KEY, bundle, document


class MemoryReader:
    def __init__(self, snapshot, on_enter=lambda: None):
        self.snapshot = snapshot
        self.on_enter = on_enter
        self.held = False
        self.exited = False

    @contextmanager
    def locked_policy(self):
        self.on_enter()
        self.held = True
        try:
            yield deepcopy(self.snapshot)
        finally:
            self.held = False
            self.exited = True


def export(reader, signed):
    return export_signed_policy(reader, *signed, ROOT_KEY.public_key(), AUDIENCE)


def test_export_uses_detached_reader_and_rechecks_under_lease(monkeypatch):
    d = document()
    reader = MemoryReader(PolicySnapshot(d['revision'], d['jwks']))
    original = ingest.VerifiedPolicy.check_current
    held = []

    def check_current(self):
        held.append(reader.held)
        return original(self)

    monkeypatch.setattr(ingest.VerifiedPolicy, 'check_current', check_current)
    result = export(reader, bundle(d))
    assert result['type'] == 'sociacl-witness-policy-envelope-v1'
    assert held == [False, True]
    assert reader.exited and not reader.held


@pytest.mark.parametrize('case', ['absent', 'revision', 'keys', 'expired'])
def test_reader_change_before_acquisition_rejects_and_releases(case, monkeypatch):
    monkeypatch.setattr(ingest.time, 'time', lambda: 1000)
    d = document()
    d.update(issuedAt=999, expiresAt=1001)
    snapshot = PolicySnapshot(d['revision'], d['jwks'])
    if case == 'absent':
        snapshot = None
    elif case == 'revision':
        snapshot = PolicySnapshot(2, d['jwks'])
    elif case == 'keys':
        snapshot = PolicySnapshot(1, {'keys': []})
    reader = MemoryReader(snapshot)
    if case == 'expired':
        reader.on_enter = lambda: monkeypatch.setattr(ingest.time, 'time', lambda: 1001)
    with pytest.raises(WitnessRejected):
        export(reader, bundle(d))
    assert reader.exited and not reader.held


def test_failed_read_cannot_export():
    def fail():
        raise OSError('storage unavailable')
    with pytest.raises(OSError):
        export(MemoryReader(None, fail), bundle())
