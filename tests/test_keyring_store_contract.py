"""The same atomic keyring contract for memory and PostgreSQL implementations."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, RLock

import pytest

from acl_service.domain.keyring_store import MAX_GENERATION, KeyringState, KeyringStore, StoreRejected
from acl_service.infrastructure.keyring_state_repo import PostgresKeyringStore
from test_keyring_state_repo import P, state_url, state_engine  # noqa: F401


class MemoryKeyringStore:
    """Independent test adapter, not a production durability option."""
    def __init__(self):
        self.rows = {}
        self.lock = RLock()

    def read_state(self, principal):
        with self.lock:
            return self.rows.get(principal)

    def observe_verified_head(self, principal, head):
        if type(head) is not int or not 0 <= head <= MAX_GENERATION:
            raise StoreRejected()
        with self.lock:
            old = self.rows.get(principal, KeyringState(0, 0, 0, b'', b''))
            if head < old.head_floor:
                raise StoreRejected()
            new = replace(old, head_floor=head)
            self.rows[principal] = new
            return new

    def compare_and_swap_verified(self, principal, *, head, kind, expected_generation, payload):
        if (type(expected_generation) is not int or not 0 <= expected_generation <= MAX_GENERATION
                or kind not in ('recovery', 'wraps') or not isinstance(payload, bytes)):
            raise StoreRejected()
        with self.lock:
            current = self.observe_verified_head(principal, head)
            field = 'recovery_generation' if kind == 'recovery' else 'wrap_generation'
            generation = getattr(current, field)
            if generation != expected_generation or generation == MAX_GENERATION:
                raise StoreRejected()
            new = replace(current, **{kind: payload, field: generation + 1})
            self.rows[principal] = new
            return new


@pytest.fixture(params=['memory', 'postgres'])
def store(request) -> KeyringStore:
    if request.param == 'memory':
        return MemoryKeyringStore()
    return PostgresKeyringStore(request.getfixturevalue('state_engine'))


def test_floor_generation_and_deletion_tombstones(store):
    assert store.read_state(P) is None
    first = store.compare_and_swap_verified(P, head=2, kind='recovery', expected_generation=0, payload=b'ciphertext')
    store.compare_and_swap_verified(P, head=3, kind='wraps', expected_generation=0, payload=b'wraps')
    deleted = store.compare_and_swap_verified(P, head=3, kind='recovery', expected_generation=1, payload=b'')
    assert deleted == KeyringState(3, 2, 1, b'', b'wraps')
    assert store.read_state(P) == deleted
    assert first == KeyringState(2, 1, 0, b'ciphertext', b'')
    assert store.read_state('b' + P[1:]) is None
    with pytest.raises(StoreRejected):
        store.compare_and_swap_verified(P, head=3, kind='recovery', expected_generation=0, payload=b'replay')
    with pytest.raises(StoreRejected):
        store.observe_verified_head(P, 2)
    assert store.read_state(P) == deleted


def test_rejected_generation_commits_floor_but_no_ciphertext(store):
    store.compare_and_swap_verified(P, head=1, kind='recovery', expected_generation=0, payload=b'old')
    with pytest.raises(StoreRejected):
        store.compare_and_swap_verified(P, head=4, kind='wraps', expected_generation=7, payload=b'bad')
    expected = KeyringState(4, 1, 0, b'old', b'')
    assert store.read_state(P) == expected
    with pytest.raises(StoreRejected):
        store.compare_and_swap_verified(P, head=3, kind='recovery', expected_generation=1, payload=b'rollback')
    assert store.read_state(P) == expected


def test_concurrent_first_writers_have_one_winner(store):
    barrier = Barrier(2)
    def attempt(payload):
        barrier.wait(timeout=10)
        try:
            return store.compare_and_swap_verified(P, head=1, kind='recovery', expected_generation=0, payload=payload)
        except StoreRejected:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, [b'one', b'two']))
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    assert store.read_state(P) == winners[0]


@pytest.mark.parametrize('field,value', [('head', True), ('head', -1), ('head', MAX_GENERATION + 1),
    ('expected_generation', False), ('expected_generation', -1), ('kind', 'unknown'), ('payload', 'plaintext')])
def test_invalid_operation_does_not_create_state(store, field, value):
    args = dict(head=1, kind='recovery', expected_generation=0, payload=b'ciphertext')
    args[field] = value
    with pytest.raises(StoreRejected):
        store.compare_and_swap_verified(P, **args)
    assert store.read_state(P) is None


def test_head_observation_and_other_store_write_share_one_order(store):
    barrier = Barrier(2)
    def observe():
        barrier.wait(timeout=10)
        return store.observe_verified_head(P, 2)
    def write():
        barrier.wait(timeout=10)
        try:
            return store.compare_and_swap_verified(P, head=1, kind='wraps', expected_generation=0, payload=b'wrap')
        except StoreRejected:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        observation, writing = pool.submit(observe), pool.submit(write)
        observation.result()
        accepted = writing.result()
    final = store.read_state(P)
    assert final.head_floor == 2
    assert final.recovery_generation == 0 and final.recovery == b''
    assert (final.wrap_generation, final.wraps) == ((1, b'wrap') if accepted else (0, b''))
