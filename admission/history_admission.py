"""Trusted adapter. The transport supplies only the record bytes and proof."""
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from acl_service.domain.history_store import HistoryConflict, HistoryStore


FORK_PREFIX = b"acl-rotation-fork-v1\x00"


class AdmissionRejected(ValueError):
    pass


class RotationFork(AdmissionRejected):
    """Conflicting authenticated rotations have frozen this account."""


@dataclass(frozen=True)
class EnrollmentGrant:
    """Provisioned for a principal created under exclusive ACL authority from genesis."""
    principal: str
    authority: str
    nonce: str
    expires_at: int


def _record(raw):
    if not isinstance(raw, bytes) or len(raw) > 128 * 1024:
        raise AdmissionRejected("invalid record size")

    def unique(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise AdmissionRejected("duplicate record property")
        return obj

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise AdmissionRejected("invalid record")
    return value


class HistoryAdmission:
    def __init__(self, store: HistoryStore, *, grant_for, trust_at, clock=time.time):
        self.store = store
        self.grant_for = grant_for
        self.trust_at = trust_at
        self.clock = clock

    def _verify(self, principal, now, **inputs):
        payload = dict(principal=principal, now=now, trust=self.trust_at(now), **inputs)
        result = subprocess.run(
            ["node", Path(__file__).with_name("verify.mjs")],
            input=json.dumps(payload, allow_nan=False).encode(), timeout=10, check=False, stdout=subprocess.PIPE,
        )
        if result.returncode or result.stdout not in (b"accepted", b"fork"):
            raise AdmissionRejected("SociACL verification failed")

        return result.stdout

    def enroll(self, principal: str, genesis: bytes, signature: str):
        now = int(self.clock())
        grant = self.grant_for(principal)
        if (not grant or grant.principal != principal or not grant.authority or
                not grant.nonce or now >= grant.expires_at):
            raise AdmissionRejected("no active enrollment grant")
        self._verify(principal, now, genesis=_record(genesis), entries=[],
                     grant=asdict(grant), signature=signature)
        if int(self.clock()) >= grant.expires_at or self.grant_for(principal) != grant:
            raise AdmissionRejected("enrollment grant changed or expired")
        self.store.enroll(principal, genesis)

    def admit(self, principal: str, record: bytes):
        candidate = _record(record)
        while True:
            try:
                return self._admit_once(principal, record, candidate)
            except HistoryConflict:
                # A verified sibling may have won the race. Re-evaluate that
                # rotation from the new committed snapshot before deciding.
                if candidate.get("kind") != "rotate":
                    raise

    def _admit_once(self, principal, record, candidate):
        snapshot = self.store.read(principal)
        if snapshot is None or snapshot.principal != principal:
            raise AdmissionRejected("no enrolled history")
        if any(row.startswith(FORK_PREFIX) for row in snapshot.entries):
            raise RotationFork("history frozen")
        rows = [_record(row) for row in snapshot.entries]
        def wallet_rotation(row):
            return (row.get("kind") == "rotate" and isinstance(row.get("authorizer"), dict)
                    and row["authorizer"].get("kind") == "wallet")

        fence = {}
        peers = None
        if wallet_rotation(candidate) or any(map(wallet_rotation, rows)):
            revision, accounts = self.store.read_authority()
            if accounts.get(principal) != snapshot:
                raise HistoryConflict("target changed during wallet lookup")
            fence["authority_revision"] = revision
            peers = []
            for owner, account in accounts.items():
                if owner == principal:
                    continue
                frozen = any(row.startswith(FORK_PREFIX) for row in account.entries)
                peers.append(dict(principal=owner, genesis=_record(account.genesis), frozen=frozen, entries=[
                    _record(row) for row in account.entries if not row.startswith(FORK_PREFIX)
                ]))
        outcome = self._verify(principal, int(self.clock()), genesis=_record(snapshot.genesis),
                               entries=rows, record=candidate, peers=peers)
        if outcome == b"fork":
            self.store.append(principal, snapshot.revision, FORK_PREFIX + record, **fence)
            raise RotationFork("history frozen")
        self.store.append(principal, snapshot.revision, record, **fence)
