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
