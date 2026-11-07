"""Trusted adapter. The transport supplies only the record bytes and proof."""
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from acl_service.domain.history_store import HistoryStore


class AdmissionRejected(ValueError):
    pass


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
            input=json.dumps(payload, allow_nan=False).encode(), timeout=10, check=False,
        )
        if result.returncode:
            raise AdmissionRejected("SociACL verification failed")

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
        snapshot = self.store.read(principal)
        if snapshot is None or snapshot.principal != principal:
            raise AdmissionRejected("no enrolled history")
        self._verify(principal, int(self.clock()), genesis=_record(snapshot.genesis),
                     entries=[_record(row) for row in snapshot.entries], record=candidate)
        self.store.append(principal, snapshot.revision, record)
