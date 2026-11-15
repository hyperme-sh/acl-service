# SEA transfer authority

Parent: hyperme-sh/spanopticon#85. Implements acl-service#163 using SDK #46 and
SociACL #205. No private key material reaches ACL. This does not enroll an
identity, grant a session, or create destination storage.

The authenticated caller needs `acl:identity:transfer`, a matching token and
`X-Tenant-ID`, and an explicit tenant/subject binding. A fresh destination must
first obtain its existing authenticated subject through auth-service; this API
does not accept a shared browser service identity or derive a subject from QR.

`POST /api/v1/acl/sociacl/device-transfer/state` accepts exactly `{scope, identity}`.
`POST /api/v1/acl/sociacl/device-transfer/current` accepts `{binding}` with optional
`expectedRevision`. `scope`, `identity`, and `binding` match SDK public types;
`binding` includes session, transcript and expiry in epoch milliseconds. Extra
fields, including keyring bytes or client history, are refused. Requests are
uncompressed JSON bounded to 4 KiB. Responses and failures are private/no-store.
Responses contain `{identity, scope, binding, at, checkpoint, history, trust}`;
`at` and history timestamps use epoch seconds, checkpoint expiry uses milliseconds.
`binding` is null for state. History is bounded to 64 accounts/4 MiB and includes
only public identity rows. It is private owner data, never telemetry.

The source reads enrolled histories under the existing protected transaction and
independent checkpoint. Existing SociACL `resolveStoreAccount` authenticates every
returned history; diagnostics, future rows, missing genesis and incomplete or
forked rotations refuse. The configured stable principal must match the current
signing/encryption keys and sequence. The checkpoint digest binds protected
history, source, transfer eligibility/trust policy, principal, scope and the full
session/transcript binding. It is opaque, not a portable bearer authorization.
Only an authenticated HTTPS response from the configured ACL is authoritative.

## Configuration and retirement

`SOCIACL_DEVICE_TRANSFER_BINDINGS_FILE` uses the existing contact binding shape:
`{version:1,bindings:[{tenant,subject,principal,postgresFile,policyFile}]}`. It opens
the already provisioned protected PostgreSQL source; it does not provision rows.
Paths must be absolute private regular files. Missing configuration disables the
endpoint; malformed bindings fail startup. Policy is reread for every operation
and again before returning, so invalid/unavailable policy always refuses.

The private policy file contains exactly `{version:1,from,until,trust,scopes,
activePrincipals}`. `trust` has the existing `{jwks,policy,pinnedIss}` shape;
`scopes` lists exact SDK scope objects (HTTPS origins only). `activePrincipals`
is an explicit transfer eligibility allowlist. `from`/`until` use epoch seconds.
Remove a retired/disabled principal from this policy. ACL currently has no general
account-retirement record in its identity journal: deployment must keep this
eligibility policy synchronized with the owning account status, in addition to
normal authenticated-subject eligibility. Missing eligibility is a refusal, not
permission inferred from possession of an old key. Signed link revocations remain
part of the canonical history checks; revoking a link does not itself revoke all
copies of a SEA identity.

## Browser adapter and final validation

`browser/device-transfer` packages `acl-sea-device-authority` independently. Its
`createAuthority({scope,request,now?})` implements the SDK `IdentityAdapter` and
exposes `keyringState(identity)` for local import/export. `request(operation,body)`
must call the above endpoint over authenticated HTTPS, bound response bytes to
4 MiB, refuse non-2xx and redirects to another origin, and supply tenant headers.
It is trusted application code, never derived from pairing data. No key bytes
are passed to this callback.

The adapter obtains fresh owner state for each validation and calls the supported
`sociacl-ids/keyring.validateKeyring`; it never copies keyring verification logic.
It supplies `historyState` only over server-authenticated complete histories.
A short-lived keyring-state callback refuses use after its checkpoint expires.
Each `current` call fetches again and compares the session's prior revision.
Use one adapter per pairing flow and call `close()` on cancellation/completion.

The SDK storage callback must acquire its destination write lock, finish local
protection work, then call `beforeCommit` immediately before atomic storage and
recheck abort/expiry. An authority change between receiver validation and this
final call refuses; refresh/restart instead of silently adopting new keys.
Decisions expire in at most five seconds and never outlive session or policy.
There is no distributed transaction between ACL and browser storage: a rotation
after the final read cannot be prevented remotely. Subsequent authentication and
access must always check current authority; a successful copy grants no rights.

CI checks protected-source units, authenticated HTTP refusal, packed declarations,
browser bundling and a synthetic SDK transfer using real SociACL keyring bytes
and the canonical ACL verifier. No live or shared TEST runs are required here.
