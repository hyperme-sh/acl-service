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

Main validation retains its exact qualified files in Actions artifacts. It does
not create GitHub releases or tags. Historical `test-<commit>` prereleases remain
qualification evidence and do not establish an accepted stable release.

Stable publication requires an explicit `vMAJOR.MINOR.PATCH` tag, the exact
successful main validation artifact, compatible declared contracts and an actual
immutable stable baseline. The publisher independently verifies that evidence;
successful caller jobs alone cannot establish acceptance. Missing evidence and
first-stable bootstrap remain closed. Package qualification, coordinated consumer
acceptance and runtime deployment remain separate.

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

## Release compatibility baseline

The accepted bundle records the published 0.1.0 artifact from the current tenant
boundary implementation, with successful main-run provenance and byte-for-byte
Actions archive verification. The 0.24.0 candidate changes metadata only. Its
complete packaged runtime, policy resources and dependency declarations match
that baseline; CI binds the declaration to the actual candidate wheel and checks
the sdist rebuild preserves the same contract. This conservative byte-level
contract detects implementation changes too, without claiming semantic compatibility.
PostgreSQL boundary regressions remain required by main package qualification;
provider and live deployment acceptance remain separate.

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained; no release, version change, deployment or human
approval prerequisite is introduced by this correction.
