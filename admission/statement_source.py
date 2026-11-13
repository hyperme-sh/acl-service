"""Single-tenant signed statement source, colocated with enrolled identity history."""
import hashlib
import hmac
import json
import secrets
import re
import time
from uuid import UUID

from history_admission import HistoryAdmission, FORK_PREFIX, _record, _peer_inputs
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict, HistorySnapshot
from acl_service.infrastructure.authority_checkpoint import authority_digest


MAX_BYTES = 4 * 1024 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class StatementSource:
    """Provision only for a new graph admitted exclusively by this source.

    No HTTP enrollment/import is provided. All identity changes must use the same
    HistoryStore. One database belongs to one tenant; each scope fixes its forum.
    Runtime bindings require the independently stored authority checkpoint.
    """
    def __init__(self, store, tenant, *, clock=time.time, verifier=None):
        self.store, self.clock = store, clock
        self.tenant = str(UUID(tenant))
        self.production_ready = store.require_authority_checkpoint and verifier is None
        self.verifier = verifier or self._verify
        with self.store._transaction(write=True) as db:
            db.execute("CREATE TABLE IF NOT EXISTS statement_tenant (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO statement_tenant VALUES(1,?)", (self.tenant,))
            if db.execute("SELECT tenant FROM statement_tenant WHERE id=1").fetchone() != (self.tenant,):
                raise AdmissionRejected("database belongs to another tenant")
            db.execute("""CREATE TABLE IF NOT EXISTS statement_scopes (
                scope TEXT PRIMARY KEY, revision INTEGER NOT NULL, nonce BLOB NOT NULL, document BLOB NOT NULL)""")

    def _guard(self, at, cancel):
        if type(at) is not int or at < 0 or int(self.clock()) != at:
            raise HistoryConflict("statement evaluation expired")
        cancel()

    def _accounts(self, db):
        size = db.execute("SELECT (SELECT COALESCE(SUM(length(genesis)),0) FROM history_accounts) + "
                          "(SELECT COALESCE(SUM(length(entry)),0) FROM history_entries)").fetchone()[0]
        if size > MAX_BYTES:
            raise AdmissionRejected("identity capacity")
        accounts = {}
        for principal, genesis in db.execute("SELECT principal,genesis FROM history_accounts ORDER BY principal"):
            entries = tuple(row[0] for row in db.execute(
                "SELECT entry FROM history_entries WHERE principal=? ORDER BY revision", (principal,)))
            if any(row.startswith(FORK_PREFIX) for row in entries):
                raise AdmissionRejected("frozen identity history")
            accounts[principal] = HistorySnapshot(principal, genesis, entries)
        if not accounts or len(accounts) > 64:
            raise AdmissionRejected("identity capacity")
        return accounts

    def _verify(self, accounts, doc, at, candidates, statement_only):
        principal = next(iter(accounts))
        account = accounts[principal]
        verifier = HistoryAdmission(self.store, grant_for=lambda _: None,
                                    trust_at=lambda _: doc["policy"], clock=self.clock)
        return json.loads(verifier._run_verifier(principal, at, genesis=_record(account.genesis),
            entries=[_record(row) for row in account.entries], peers=_peer_inputs(principal, accounts),
            graph={"forum": doc["forum"], "rows": doc["rows"], "candidates": candidates,
                   "statementOnly": statement_only}))

    @staticmethod
    def _digest(revision, nonce, document):
        return hashlib.sha256(encoded(revision) + nonce + document).digest()

    def _checkpoint(self, db, scope, row, *, write=False):
        if not self.store.require_authority_checkpoint:
            return
        digest = hashlib.sha256(encoded([self.tenant, scope]) + self._digest(*row)).digest()
        if write:
            db.execute("INSERT INTO freshness.statement_checkpoints VALUES(?,?) "
                       "ON CONFLICT(scope) DO UPDATE SET digest=excluded.digest", (scope, digest))
        elif db.execute("SELECT digest FROM freshness.statement_checkpoints WHERE scope=?", (scope,)).fetchone() != (digest,):
            raise AdmissionRejected("statement checkpoint mismatch")

    def _load(self, db, scope, at):
        row = db.execute("SELECT revision,nonce,document FROM statement_scopes WHERE scope=?", (scope,)).fetchone()
        if row is None:
            raise AdmissionRejected("statement source not provisioned")
        self._checkpoint(db, scope, row)
        doc = json.loads(row[2])
        if type(doc["policyUntil"]) is not int or at >= doc["policyUntil"]:
            raise AdmissionRejected("statement policy expired")
        return row, doc

    def _fence(self, db, scope, row, at):
        message = encoded([self.tenant, scope, at, row[0], hashlib.sha256(row[2]).hexdigest(),
                           authority_digest(db).hex()])
        return hmac.new(row[1], message, hashlib.sha256).hexdigest()

    def provision(self, scope, forum, policy, policy_until, *, exclusive_grant):
        """Operator-only creation, empty rows, no imported snapshot or history.

        exclusive_grant(scope, forum) must independently attest that this new
        graph is exclusively admitted here. It is rechecked at commit.
        """
        if not isinstance(scope, str) or not scope or len(scope) > 128:
            raise AdmissionRejected("invalid scope")
        at = int(self.clock())
        def guard():
            self._guard(at, lambda: None)
            if not exclusive_grant(scope, forum):
                raise AdmissionRejected("no exclusive graph grant")
        guard()
        doc = {"forum": forum, "rows": [], "policy": json.loads(encoded(policy)), "policyUntil": policy_until}
        if type(policy_until) is not int or policy_until <= at or len(encoded(doc)) > MAX_BYTES:
            raise AdmissionRejected("invalid policy")
        with self.store._transaction(write=True, before_commit=guard) as db:
            self.verifier(self._accounts(db), doc, at, [], False)
            row = (0, secrets.token_bytes(32), encoded(doc))
            if db.execute("SELECT 1 FROM statement_scopes WHERE scope=?", (scope,)).fetchone():
                raise HistoryConflict("scope already provisioned")
            db.execute("INSERT INTO statement_scopes VALUES(?,?,?,?)", (scope, *row))
            if self.store.require_authority_checkpoint:
                db.execute("CREATE TABLE IF NOT EXISTS freshness.statement_checkpoints (scope TEXT PRIMARY KEY, digest BLOB NOT NULL)")
                if db.execute("SELECT 1 FROM freshness.statement_checkpoints WHERE scope=?", (scope,)).fetchone():
                    raise AdmissionRejected("scope checkpoint already exists")
                self._checkpoint(db, scope, row, write=True)

    def read(self, scope, at, cancel=lambda: None):
        self._guard(at, cancel)
        with self.store._transaction(write=True, before_commit=lambda: self._guard(at, cancel)) as db:
            row, doc = self._load(db, scope, at)
            result = self.verifier(self._accounts(db), doc, at, [], False)
            self._guard(at, cancel)
            for principal, head in result["heads"].items():
                self.store._observe_floor(db, principal, head)
            return {"snapshot": result["snapshot"], "fence": self._fence(db, scope, row, at)}

    def append(self, scope, at, fence, rows, cancel=lambda: None, *, statement_only=True):
        self._guard(at, cancel)
        if not isinstance(fence, str) or not re.fullmatch(r"[0-9a-f]{64}", fence) or not isinstance(rows, list) or not 1 <= len(rows) <= 65 or len(encoded(rows)) > 65536:
            raise AdmissionRejected("invalid append")
        # Detach caller-owned input before verification or mutation.
        rows = json.loads(encoded(rows))
        with self.store._transaction(write=True, before_commit=lambda: self._guard(at, cancel)) as db:
            held, doc = self._load(db, scope, at)
            if not hmac.compare_digest(fence, self._fence(db, scope, held, at)):
                raise HistoryConflict("statement source changed")
            result = self.verifier(self._accounts(db), doc, at, rows, statement_only)
            snapshot = result["snapshot"]
            if len(snapshot["rows"]) > 1024 or len(encoded(snapshot)) > MAX_BYTES:
                raise AdmissionRejected("statement capacity")
            for principal, head in result["heads"].items():
                self.store._observe_floor(db, principal, head)
            if doc["rows"] == snapshot["rows"]:
                return True
            doc["rows"] = snapshot["rows"]
            next_row = (held[0] + 1, held[1], encoded(doc))
            db.execute("UPDATE statement_scopes SET revision=?,nonce=?,document=? WHERE scope=?", (*next_row, scope))
            self._checkpoint(db, scope, next_row, write=True)
        return True

    def replace_policy(self, scope, expected_revision, policy, policy_until, *, authorize):
        """Operator-only policy update invalidates outstanding fences."""
        at = int(self.clock())
        def guard():
            self._guard(at, lambda: None)
            if not authorize(scope, policy, policy_until):
                raise AdmissionRejected("policy update not authorized")
        guard()
        policy = json.loads(encoded(policy))
        if type(policy_until) is not int or policy_until <= at:
            raise AdmissionRejected("expired policy")
        with self.store._transaction(write=True, before_commit=guard) as db:
            held = db.execute("SELECT revision,nonce,document FROM statement_scopes WHERE scope=?", (scope,)).fetchone()
            if held is None or held[0] != expected_revision:
                raise HistoryConflict("policy source changed")
            self._checkpoint(db, scope, held)
            doc = json.loads(held[2]); doc.update(policy=policy, policyUntil=policy_until)
            self.verifier(self._accounts(db), doc, at, [], False)
            row = (held[0] + 1, held[1], encoded(doc))
            if len(row[2]) > MAX_BYTES:
                raise AdmissionRejected("policy capacity")
            db.execute("UPDATE statement_scopes SET revision=?,nonce=?,document=? WHERE scope=?", (*row, scope))
            self._checkpoint(db, scope, row, write=True)
