# Recovery and wrap adapter inventory

Audited ACL-service main at `d57c954` for [#14](https://github.com/hyperme-sh/acl-service/issues/14). The table traces the service source that ships in the package. Live rollout and durable recovery API qualification are tracked in [#13](https://github.com/hyperme-sh/acl-service/issues/13).

| Entry point | Storage path | Evidence available to the caller |
| --- | --- | --- |
| `POST /api/v1/acl/sociacl/recovery/sessions` | The [handler](../src/acl_service/interfaces/api/sociacl_routes.py) calls `RecoveryStore.create_or_get_session`. The [app factory](../src/acl_service/app.py) supplies `PostgresRecoveryStore`. | An authenticated tenant member can create or retry a tenant-scoped workflow session. Its idempotency key and metadata identify that operation. |
| `POST /api/v1/acl/sociacl/recovery/sessions/{session_id}/proof` | The same handler module calls `transition_state` on the session store and records `awaiting_proof`. | The handler ignores the submitted proof body. Its success response acknowledges a state transition. Chain verification and key release require separate evidence. |
| `GET /api/v1/acl/sociacl/witness-policy` | The [policy route](../src/acl_service/interfaces/api/witness_policy_routes.py) serves configured signed policy. | Policy authenticates witness configuration. Establishing completeness of an individual account's history requires a separate trusted source. |
| Recovery and wrap ciphertext | The [KeyringStore interface](../src/acl_service/domain/keyring_store.py) exposes `read_state`, `observe_verified_head` and `compare_and_swap_verified`. The [PostgreSQL adapter](../src/acl_service/infrastructure/keyring_state_repo.py) serializes both stores on one principal row. | These operations accept already verified inputs. The app factory and registered HTTP routes have no injected keyring verifier or caller of these mutations. |

## Connecting a verifier

The [SociACL recovery store contract](https://github.com/FyberLabs/SociACL/blob/a1fb609b67a581b99d09bac2775d72b1a2d3b88e/docs/recovery-store-operations.md) defines the input to TypeScript `resolveStoreAccount` and Rust `resolve_store_account`. The service integration needs three boundaries:

1. Load the principal's authenticated, complete, fresh history from the authoritative source. Supply rotations, links, revocations, genesis encryption-key bindings and trusted witness policy. A caller's claimed head, tenant login, or high index sequence cannot establish this snapshot.
2. Run the shared resolver over that snapshot and collect diagnostics for this operation. Malformed entries can be skipped. A valid rotation fork rejects resolution. Propagate the refusal before either ciphertext store can mutate. Preserve the accepted current signing key, encryption key when known, and chain for package-level operation verification.
3. Bind the accepted head to the same per-principal floor for recovery and wraps. The storage API serializes each floor observation and checks the floor again at compare-and-swap. A stale generation can reject the ciphertext update while committing a higher verified floor. On an ambiguous write result, read durable state before re-verifying and re-signing. Keep the floor and generation evidence on ciphertext deletion.

The adapter-level acceptance cases still needed are a forged high sequence, a malformed record alongside valid history with diagnostics, a valid fork, stale or incomplete history, and request-supplied resolver inputs. Exercise each through the eventual caller and assert its effect on the shared floor and both ciphertext stores. Existing [storage tests](../tests/test_keyring_state_repo.py) exercise locking and persistence. The production history source, package verifier binding, and authenticated recovery/wrap endpoints remain open.

## Enrolled history storage

ACL-service owns complete history for principals whose identity changes it
admits from genesis. Existing peer histories and previously managed principals
cannot be enrolled by importing a snapshot. An unenrolled principal has no
authoritative snapshot here.

The internal [HistoryStore](../src/acl_service/domain/history_store.py) API
accepts opaque admitted record bytes. Its single-host SQLite implementation
persists genesis once, appends against the expected revision and reads an
atomic snapshot. Use one database for all callers in that deployment.
Independent replica-local files cannot serve the same authority. A retry
after an ambiguous commit must reread history before admitting another entry.

This backend is available for qualification. Production activation still
requires exclusive authenticated enrollment and record admission, the package
verifier, and serialization of the resolved snapshot revision with the final
floor/ciphertext operation. A subsequent admission can invalidate a snapshot
immediately after a read. No HTTP route currently grants enrollment or
accepts caller-supplied history.

### Authenticated admission qualification

The internal adapter in `admission/history_admission.py` accepts an independently
provisioned exclusive-from-genesis grant and a service-owned witness policy
provider. Provisioning must establish that the principal was created under
this authority. Possession of an existing signing key alone cannot establish
exclusive history. The grant issuer supplies an unpredictable nonce and an
expiry. The genesis key signs SociACL length-prefixed UTF-8 fields in order:
`acl-service-history-enrollment-v1`, authority, principal, nonce, decimal
expiry in Unix seconds, and the SociACL record ID of the witnessed genesis
encryption-key binding. The verifier authenticates both proofs before the
storage API creates the immutable account.

The adapter admits wallet links, OIDC links and witnessed
revocations. It reads one enrolled snapshot, verifies the candidate using
the pinned SociACL package, and submits the original bytes with the expected
revision. Storage conflicts require reverification. Link admission authenticates the record.
OIDC rotation admission replays committed rotations, verifies a new transition
with the SociACL resolver and publication rules, and rechecks after a revision
conflict. Subsequent records must postdate the last transition and verify under
the current key. A fully verified sibling persists the exact evidence prefixed
with the internal fork marker in one revision-checked append. Admission then
raises RotationFork, including after restart. A reader must reject a marked
snapshot before resolving any key. Wallet rotations resolve competing claims across the enrolled authority at
issuance and again before admitting a new head. The latter lookup must select
the exact authorizing link. The verifier replays relevant competing accounts'
chains and fails closed when their history is frozen or unavailable. A wallet
rotation, fork observation, or subsequent admission depending on a wallet
rotation commits against both the principal revision and the revision of the
whole authority. Concurrent admissions invalidate that snapshot.

The SQLite qualification backend scans the enrolled ledger in one transaction.
Only use this path for a namespace whose wallet-link evidence is complete in
that ledger. It cannot establish ownership across independent authorities.

From `admission/`, use Node 24, run `npm ci --ignore-scripts`, then
`PYTHONPATH=../src python3 -m unittest -v test_admission`. Fixtures are
synthetic cases from SociACL records.json at the revision pinned in the
package lock, plus a domain-specific enrollment signature. This adapter runs
from the checkout and has no public HTTP or container entry point yet.

### Shared head observation

The internal `observe_store_head(principal)` adapter resolves the enrolled ledger
with service-selected time and witness policy. It returns the authenticated
sequence, signing key, encryption key and resolver diagnostics only after the
SQLite backend commits the principal's monotonic floor. An authority revision
change during verification rejects the observation. A new rotation commits its
floor in the same transaction as its admission. The first successful observation
also initializes the floor for a ledger created before this change.

This qualification floor belongs to the SQLite ledger. A production adapter
must colocate its authority fence, floor and ciphertext compare-and-swap, or
provide equivalent atomic semantics. An observation alone cannot authorize a
subsequent key release or ciphertext mutation.

### Signed ciphertext writes

The checkout adapter accepts `apply_store_operation(principal, kind, operation)`
for the enrolled ledger. Store kinds are `recovery` and `wraps`. Recovery
supports put, commit of a pending copy, and delete by rotation sequence. Wraps
support put and delete by wrap ID. The request carries the action, signature,
and row or target required for that action. Recovery envelope bytes use lowercase
hex in `bytesHex`. See `admission/store-fixture.json` for signed examples generated
with the pinned SociACL reference functions signStoreWrite, recoveryEnvelopeHash,
and wrapRowHash.

The adapter derives the head and current signing key from the verifier, and
the generation and previous row hash from durable ciphertext state. SQLite
holds its write lock while comparing the authority revision, checking the
shared floor, comparing the store generation, and writing the new state.
Deletion retains the generation. On a conflict, reread the authority and store
state before signing another operation. These internal operations qualify
ciphertext storage; opening a recovery copy requires independent decryption
and keyring validation. Production transport and deployment remain open.

### Authenticated HTTP writes

`POST /api/v1/acl/sociacl/keyring/{kind}/operations` accepts the signed JSON
operation described above. Use `recovery` or `wraps` for the store kind. The bearer
token and matching `X-Tenant-ID` select a provisioned (tenant UUID, token subject)
binding. The app factory copies the supplied `signed_store_bindings` mapping at
construction. Each binding holds the enrolled principal and its trusted writer.
The operation body cannot select the account, ledger, trust policy or verifier.

A successful write returns the committed generation. A verifier rejection returns
403; a concurrent authority or storage conflict returns 409. A client must reread
and re-sign before attempting a conflicting write. The standalone application
returns 503 until its deployment supplies bindings and an authoritative writer.
The HTTP acceptance fixture uses synthetic token identities and the enrolled
SQLite ledger with actual signed recovery and wrap operations.

The standalone runtime image carries the trusted Python writer, its Node runtime
and its lockfile-verified SociACL dependencies under image ownership. Deployment
launchers can import `history_admission` from `/opt/acl-admission`. Both the image
build and archive replay exercise enrollment and signed writes offline. Authority
history, witness trust and tenant/subject bindings must come from the deployment.

For a single-host deployment with separately restored ciphertext freshness state,
initialize the record once with writers stopped, from an independently pinned,
standalone backup of the current ledger:

```sh
python -m acl_service.infrastructure.initialize_ciphertext_freshness \
  --snapshot /backup/history.sqlite --sha256 "$CHECKPOINT_SHA256" \
  --output /freshness/ciphertext.sqlite
```

Give the service write access to the freshness file and its journal directory.
Construct the store with `freshness_path` pointing to that file. Both databases
must support SQLite rollback journals and durable local filesystem locking.
Recovery and wrap reads compare generation and payload digest. Writes repeat
the comparison under the SQLite write lock and advance both records in a
single attached-database transaction. An unprovisioned principal fails closed.
Keep the freshness file outside the ledger restore scope. Rolling both files
back together is outside this guarantee, as is rollback of authority history
alone. The TEST startup checkpoint remains a separate deployment control.

### Authority snapshot freshness

For a bounded single-host ledger, `require_authority_checkpoint=True` enables
authority verification on the same store. The initializer records a canonical
digest of every principal's genesis bytes, ordered history entries (including
fork markers), and durable head floor. Reads check the digest inside their
snapshot. Writes check it again under the write lock and update the checkpoint
in the transaction that commits the change. This includes the final ciphertext
commit and changes to another principal's history. Cost scales with the full
authority history on each checked transaction.

Existing ciphertext-only deployments continue in their configured mode. Before
enabling authority checks, quiesce writers and independently establish that a
new standalone ledger backup has current, complete authority history and matches
the advancing ciphertext heads. Initialize a **new** freshness file from its
pinned digest and retain the old one for reconciliation. A legacy freshness
file lacks the authority checkpoint and cannot serve authority-checked requests.
All writers to the ledger must then use authority checking.

The checkpoint authenticates continuity after that trusted baseline. The
verifier's witness keys, issuer and admission policy still need a separately
authenticated source; changes in those inputs are not ledger entries.
