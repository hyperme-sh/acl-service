# ACL service

## Current version authority

Current development version: `0.1.0`. The services remain before the unreleased
0.24.0 milestone. Earlier 0.24/1.0 preparation and publication notes below are
historical and do not authorize those versions. Existing tags and historical
artifacts remain untouched. Development uses exact source pins and rebuilt
artifacts; no prior release is required. Version changes, tags and publication
require the owner's explicit authorization to the agent.

Tenant authorization, Casbin policies and SociACL witness/keyring interfaces.
First-party code is Apache-2.0 licensed; dependency wheels retain their own licenses.
Runtime: src/acl_service; factory: acl_service.app.create_app.

## Development

Use Python 3.13, uv 0.11.26 and Docker. The credential-free qualification lane
uses verified dependency wheels built from the exact source pins:

    bash scripts/check-package.sh --fixtures

The active `tests/` suite includes the transferred PostgreSQL/RLS, policy HTTP,
checkpoint replay, keyring persistence and witness tests. Disposable PostgreSQL
17 containers run the installed database package's migrations. Required Docker
or migration failures fail qualification; cases cannot silently skip. Source,
fresh-wheel and rebuilt-sdist runs must pass the same nonempty case inventory.
Wheel runtime, policy resources, SPDX metadata and Apache license bytes are checked.
`tests/panopticon-transfer-provenance.json` records immutable source hashes and
adaptations to the current owner security boundaries. The archived
`core/acl-service/tests` tree is historical, not the CI test entry point.

Private CI runs on debrunners. The preparation lane needs no private credentials;
the normal dependency-build lane uses short-lived GitHub App tokens scoped to the
listed dependency repositories. Tests use generated keys and disposable data.
They do not activate a live identity provider, publish policies or deploy services.

## Policy administration

Creating or deleting policies requires a preexisting tenant RBAC grant for
`user:<authenticated-subject>`, resource `/acl/policies`, action `manage`.
Provision the initial administrator through a trusted owner-controlled bootstrap
path; ordinary tenant membership cannot grant this permission through the API.

Shares requiring verification level or vouch count deny access until a trusted,
same-tenant attribute or attestation resolver is implemented. Caller context and
authentication alone do not establish these attributes, including zero thresholds.

Distance, political-tolerance and handle allow/block restrictions also deny until
trusted evidence is available, including omitted handles and explicit empty lists.
Only unrestricted context predicates and separately verified group membership
can proceed; caller source labels do not establish provenance.

## Release channels

Successful main-push validation retains the validated Python wheel and source
distribution as Actions artifacts. Push a `vMAJOR.MINOR.PATCH` tag at that tested
commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Main builds create no GitHub release or reserved stable version. Stable assets
are GitHub distributions, not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

### Immutable release candidate validation

The candidate job builds and uploads `tested-dist` immediately after the build, before running repository validators or tests. Source tests run in their own job. Only after they pass does a separate job
download that exact artifact ID and run fresh-wheel and rebuilt-sdist checks
against a disposable copy. Expected hashes remain in the invoking shell and
are rechecked after validation; neither downloaded nor staged distributions
may be replaced by tests. Tests cannot replace the
already uploaded candidate through a post-test staging step: validation never
uploads artifacts. The publisher requires the entire main-push workflow to
succeed and promotes only the immutable candidate. Failed validation leaves an
unpublished candidate, not a successful release. Both jobs keep the existing
shared-runner policy; this is artifact immutability, not host isolation.

To validate a previously built candidate locally, set `RELEASE_CANDIDATE_DIR` to
a directory containing exactly its wheel and source distribution when invoking
`scripts/check-package.sh`. With no candidate directory, the ordinary local
build-and-test path is unchanged.

## Standalone container

The root Dockerfile installs the frozen dependencies and maintained ACL package
non-editably. The runtime contains only the installed environment, runs as UID
10001, and does not use PYTHONPATH or the retired monorepo source tree.

With an existing read credential supplied in the shell environment:

```sh
docker build --secret id=dependency_read_token,env=DEPENDENCY_READ_TOKEN -t acl-service:local .
bash scripts/check-image.sh acl-service:local
```

BuildKit mounts the credential only for dependency installation. Repository-scoped
Git headers exist in that process environment; no credential or Git configuration
is copied into the runtime. Never pass credentials as build arguments.

The image check compares installed runtime/resource hashes with src/acl_service
and exercises the real application routes through ASGI HTTP in a read-only,
network-disabled container. Auth, storage and event publishing use deterministic
fixtures. It covers policy self-grants, authorized administration, tenant
mismatch, spoofed group subjects, and untrusted identity/context predicates.
These checks do not qualify real Keycloak, PostgreSQL/RLS, event transport,
startup against configured services, or deployment. The image is not published
or deployed by this workflow. CI runs image qualification after immutable
package validation; the existing package publisher still requires the full
workflow to succeed.

## Native PostgreSQL boundary checks

Run `bash scripts/check-postgres.sh` with Docker available and dependency read
access configured. It installs the locked package non-editably and creates a
unique PostgreSQL 16 container, bound only to a random loopback port, then applies
the pinned DB package's owner migrations. It accepts no external database URL;
the container and its volumes are removed even if a test fails. Docker or migration
failures fail the check rather than skip it.

The 12 database regressions adopted from Panopticon #691 cover transaction-local
tenant context after commit/refresh, foreign-row invisibility, RBAC/ABAC policy
loading, and active issuer-subject membership across user, group and membership
tenants. Operations use a role with neither superuser nor RLS-bypass privileges.
CI runs these against the immutable candidate wheel in the package job, before
image qualification. The active package suite additionally exercises HTTP introspection, MFA and
account-lifecycle guards with the pinned auth package and controlled test responses.
These checks do not establish live identity-provider acceptance.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. Owning-package and artifact validation
remain separate from stable release admission. Future test receipts must carry
an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. The merged initial-admission path validates the explicit
candidate and checks complete live history when no baseline is selected. The
publisher independently validates owning metadata and exact tested bytes, then
atomically claims the initial source. Later releases require an actual stable
baseline. Both shared pins reference merged implementations.
Live deployment and coordinated consumer acceptance remain separate; no reviewer
or approval gate is added.

## Artifact qualification

The historical qualification records the test-published 0.1.0 artifact from the current tenant
boundary implementation, with successful main-run provenance and byte-for-byte
Actions archive verification. The current 0.1.0 qualification includes the transferred checkpoint replay
module and Apache-2.0 packaging; CI binds the declaration to the actual candidate wheel and checks
the sdist rebuild preserves the same contract. This conservative byte-level
contract detects implementation changes too, without claiming semantic compatibility.
PostgreSQL boundary regressions remain required by main package qualification;
provider and live deployment acceptance remain separate.

### Preparation artifacts

The read-only PR lane uploads a preparation candidate before running repository
validators, then downloads that exact artifact ID in a separate job. Source,
fresh-wheel and rebuilt-sdist consumers use verified fixtures built from the
current exact private Git pins. Expected candidate hashes remain in the invoking
shell and are rechecked; validation uploads evidence, never replacement packages.

`bash scripts/check-package.sh --fixtures` selects this credential-free consumer
lane locally. The fixture manifest records exact clean source revisions and
digests; these are not published or accepted synchronized baselines. The retained
artifact is qualified only when both jobs pass. Full-stack credential-free deployment and live provider acceptance remain
separate from package qualification. Preparation does not create tags, publish or deploy.

### Retained runtime qualification

Successful main image checks retain `tested-runtime` as a private Actions
artifact for 30 days (subject to organization retention). It contains the exact
checked image as `runtime.docker.tar` and `runtime-provenance.json`, which binds
its archive checksum, local image ID, image config digest, Linux/amd64 platform, source revision,
and Actions run/attempt. Checks and export use the immutable local image ID.
The archive config digest and embedded owner/source labels are verified before
upload; no candidate code is imported by the recorder.

This is deployment preparation. A Docker image config digest is not a registry
manifest digest. Nothing is pushed to a registry, released or deployed by this
step. Future publication needs the user's explicit approval, retained exact-byte
evidence, and separate live authorization/consumer acceptance. Do not rebuild an
expired archive and claim it is the originally qualified image. Package
`tested-dist` evidence and its release publisher remain separate.


The recorder supports both classic Docker config IDs and containerd manifest/index
IDs. For containerd it verifies each referenced metadata digest and size down to
the saved config, selecting exactly one Linux/amd64 runtime. The local image ID
and config digest are recorded separately. No registry publication is inferred.

A separate `runtime-replay` job downloads the exact artifact ID emitted by the
image job. Before loading it, the verifier compares the archive and receipt with
the independently passed image ID, archive checksum, source and Actions run/attempt.
It refuses archives containing repository tags. The job then loads the archive
and repeats the network-isolated runtime checks without dependency credentials or
the private-dependency environment. Newly loaded images and temporary files are
cleaned up. This verifies retained-image replay; live test deployment and tenant
integration acceptance still remain separate work.

For read-only retrieval and staging of a retained runtime, see
[runtime preparation](docs/runtime-preparation.md). The preparation tool verifies
live GitHub qualification evidence and stages exact bytes without loading,
publishing or deploying the image.


Retained-runtime replay also performs an owned startup check with disposable
PostgreSQL and the real app/event lifecycle. It verifies readiness, rejected
missing/malformed credentials, tenant-scoped policy creation, restart persistence
and idempotent redelivery. This uses no live credentials or existing database;
external identity, production RLS and deployed-service acceptance remain separate.
See [runtime preparation](docs/runtime-preparation.md) for scope and invocation.

## Storage and event API boundary

Policy routes, authorization evaluation and user-created handling depend on the
service-owned `PolicyStore` API, not SQLAlchemy engines or ORM rows. Composition
in `app.py` currently selects `PostgresPolicyStore`. Sessions, tenant RLS context
and commits stay inside the adapter; callers receive immutable records.
Successful mutations are visible to subsequent reads, including revocation.
Deletes match the entire rule. Storage failures propagate rather than granting
access or reporting successful event processing.

The same contract tests run against an independent in-memory test adapter and
owned PostgreSQL. The test adapter is not a production durability option.
Events use the existing tenant publisher/routing APIs, supporting PostgreSQL
and Service Bus. Publication after a committed mutation is a separate operation:
redelivery retries publication with an idempotent insert. This does not claim
an atomic database-and-bus transaction.

This is the policy-storage boundary, not a completed service-wide migration:
SociACL share/keyring repositories and request-session middleware still
require database adapters, and application startup still requires PostgreSQL.
Those boundaries must be converted before claiming a database-free deployment.
No generic remote SQL proxy or new database microservice is introduced.

Recovery-session routes also use a service-owned `RecoveryStore` API. The default
PostgreSQL adapter serializes creation for the same tenant/idempotency key and
returns immutable snapshots. Retrying creation preserves state, expiry and
metadata; HTTP responses/events reflect the committed state. Transitions scope
both tenant and session ID, including when the database role bypasses RLS.
The contract runs against memory, administrative PostgreSQL and restricted-role
PostgreSQL, including concurrent retries and cross-tenant rejection.

This API stores recovery workflow metadata; it does not verify recovery proofs,
release key material or expand authorization. The existing proof endpoint still
only requests the `awaiting_proof` state. Publication remains separate from the
storage commit. Advisory locking protects writers using this adapter; direct SQL
writers must not bypass it. Existing duplicate historical rows are not repaired
by this change. Share/keyring/witness repositories and session middleware remain
separate conversion work before PostgreSQL can become optional for the full app.

### Verified keyring storage API

`domain.keyring_store.KeyringStore` defines the storage boundary for verified
keyring ciphertext operations. `PostgresKeyringStore` owns its engine and delegates
to the existing transactional adapter. State records, rejection errors and numeric
limits are backend-neutral; existing engine-taking functions remain compatibility
helpers within the PostgreSQL adapter.

Every backend must serialize both ciphertext stores and their history floor per
principal. Successful writes are committed before returning. A stale generation
rejects the ciphertext change but still commits a newly verified floor; stale
heads change nothing. Deletion keeps the generation/floor tombstones. Ambiguous
commits require re-reading and re-verifying/re-signing, never blind retries.
Shared memory/PostgreSQL contract tests exercise these rules and concurrent
writes/observations; the memory implementation is only a test adapter.

This API assumes a trusted caller has already verified the canonical principal,
complete fresh history, signatures and envelope semantics. It does not implement
that verifier, create an HTTP endpoint, authorize recovery, or activate deployment.
Existing PostgreSQL durability/security tests remain. Share/witness repositories
and session middleware still need conversion before the complete runtime can run
without PostgreSQL.

### Membership lookup boundary

SociACL evaluation takes a `MembershipReader` rather than an engine. The default
PostgreSQL adapter owns the user/group join and preserves explicit tenant checks
on all three records, verified subject matching, active-user checks and deletion
checks. Caller-supplied context cannot establish membership. Reads are uncached;
a committed deactivation affects the next evaluation. Backend errors propagate
instead of producing an allow decision. Evaluation runs outside the async HTTP
loop, and no SQL or ORM type is imported by the predicate evaluator.

The optional Casbin gate takes the existing `PolicyStore` API independently of
membership storage. If explicitly required, it denies when its trusted subject
or store is missing, and reads current same-tenant policy. This does not enable
the optional gate on existing routes or add a new caller permission.

Share creation, token lookup and use consumption still use the PostgreSQL share
adapter directly; witness storage and request-session middleware also remain to
convert. The complete runtime still requires PostgreSQL. Replacing the membership
adapter must preserve current authorization evidence and revocation semantics.

### Share storage and active-use reservation

Share routes now use `ShareStore` and detached `ShareRecord` snapshots. PostgreSQL
owns token generation, hashed-token lookup, RLS sessions and reservation locking;
raw tokens are returned only by creation, and snapshots expose neither tokens nor
hashes. Nested metadata is copied so callers cannot mutate stored state through a
snapshot. Listing filters metadata by the authenticated creator unless the caller has an
explicit same-tenant share-management grant.

Evaluation reserves an active use before publishing an allow/notify decision.
The PostgreSQL adapter locks the tenant/share row, checks revocation and expiry
after acquiring the lock, then commits a finite decrement before returning true.
A failed reservation produces `deny/share_unavailable`, including concurrent
requests that evaluated the same one-use snapshot. Storage errors cannot emit an
approval. Unlimited shares still require a current active-state check. A later
publication/response failure can consume a use without delivery; there is no
unsafe refund or blind retry, and no claim of atomic database-and-bus delivery.

All synchronous share operations and membership evaluation run outside the async
HTTP loop. Shared memory/administrative PostgreSQL/restricted-role PostgreSQL
contract tests cover token boundaries, tenant isolation and concurrent consumption;
HTTP tests cover stale approvals, storage failure and slow operations. Witness
storage and session middleware remain to convert before PostgreSQL is optional
for the complete runtime. No new production storage backend is selected here.

### Share metadata authorization

`GET /acl/sociacl/shares` returns only rows whose `created_by` matches the verified
authentication subject. Creation sets this field server-side. A same-tenant Casbin
grant for `user:<subject>`, resource `/acl/sociacl/shares`, action `manage` allows
listing all shares in that tenant. Neither query parameters, a declared owner UUID,
nor a foreign-tenant policy grants this access. Owner UUIDs are metadata, not a
verified mapping to the authentication subject. Assigned-owner access requires a
trusted identity mapping before it can be supported; creators and managers work
without one. Legacy rows without a creator are visible only to managers.

The storage API requires explicit creator scope, applies it in the PostgreSQL
query, and accepts an unfiltered scope only from trusted management authorization.
Policy lookup failure propagates without reading share metadata. Revoking a grant
affects the next listing. Raw tokens and hashes remain excluded. This tightens
listing authorization without changing public token resolution or share creation.

## Witness policy read boundary

Public policy export uses `WitnessPolicyReader.locked_policy()`, a semantic
storage interface. Its context holds serialization against policy updates until
export has rechecked expiry and matched the exact installed revision and keys.
The PostgreSQL adapter holds a shared row lock; alternate backends must provide
an equivalent read lease, not an unlocked cached snapshot. Signed input bytes
are returned unchanged. Storage failures remain unavailable, never last-good
fallbacks. Reader snapshots are detached from persistence.

Signed policy installation now uses `WitnessPolicyWriter.install_verified()`.
The writer must recheck authorization while serialized against other readers
and writers, including same-revision retries, and atomically preserve retirement
history. The CLI selects the PostgreSQL adapter; signature and audience checks
remain outside persistence. No network write endpoint is introduced.

Complete checkpoint snapshots now consume `WitnessPolicyHistoryReader` through
all continuity, authorization and replay callers. The PostgreSQL adapter returns
detached current policy and complete retirement history under one shared lock,
held through checkpoint signing and final policy-expiry checks. Missing history
is rejected, not reconstructed from active keys. A storage exit failure discards
the response. These records are trusted storage state; current policy signatures
do not independently authenticate historical completeness.

Timestamp signing and challenge-replay writes still require storage boundaries;
no replacement persistence backend is deployed. Publication remains
default-off with its existing configuration. Independent root custody, deployed reader privileges,
edge controls, consumer freshness and management-authority acceptance in #15
remain required; package qualification does not establish those results.
