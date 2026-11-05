# ACL service

Tenant authorization, Casbin policies and SociACL witness/keyring interfaces.
Version 0.24.0. Runtime: src/acl_service; factory: acl_service.app.create_app.

## Development

Use Python 3.13 and uv 0.11.26 with read access to the nine pinned private
dependency repositories listed in .github/workflows/package.yml.

    uv sync --frozen
    bash scripts/check-package.sh

The standalone suite validates witness signatures and expiry, the interoperability
fixture, user-created event handling and packaged RBAC/ABAC models. Checks run
from source, a normal fresh wheel outside this checkout and a rebuilt sdist wheel.
Wheel runtime and policy resource bytes must match source.

Original database, checkpoint, policy lifecycle and HTTP integration tests and
fixtures remain under core/acl-service as owner integration references. The
divergent historical runtime, package metadata and monorepo Dockerfile have been
removed. PostgreSQL/RLS, concurrency and live consumer acceptance remain separate.

The main-only shared-runner workflow uses pinned actions, read-only contents and exact
repository credential headers. CI requires DEPENDENCY_READ_TOKEN access to the pinned private dependencies. No live policy, signing
key, identity, publishing or deployment operation occurs.

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
image qualification. Historical HTTP introspection/MFA/account-lifecycle acceptance
from #691 still needs coordinated auth dependencies; these database checks and
the fixture-based container routes do not establish live identity acceptance.

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
that release exists. With no baseline selected, the initial-admission path
validates the explicit 0.24.0 candidate and confirms there is no stable release.
The publisher independently validates policy and tested bytes, then atomically
claims the initial source before publishing. Subsequent tags require genuine
stable provenance and compatibility admission. Live deployment and coordinated
consumer acceptance remain separate; no reviewer or approval gate is added.

## Artifact qualification

The historical qualification records the test-published 0.1.0 artifact from the current tenant
boundary implementation, with successful main-run provenance and byte-for-byte
Actions archive verification. The current 0.24.0 qualification changes metadata only. Its
complete packaged runtime, policy resources and dependency declarations match
that snapshot; CI binds the declaration to the actual candidate wheel and checks
the sdist rebuild preserves the same contract. This conservative byte-level
contract detects implementation changes too, without claiming semantic compatibility.
PostgreSQL boundary regressions remain required by main package qualification;
provider and live deployment acceptance remain separate.
