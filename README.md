# ACL service

Tenant authorization, Casbin policies and SociACL witness/keyring interfaces.
Version 0.1.0. Runtime: src/acl_service; factory: acl_service.app.create_app.

## Development

Use Python 3.13 and uv 0.11.26 with read access to the nine pinned private
dependency repositories listed in .github/workflows/package.yml.

    uv sync --frozen
    bash scripts/check-package.sh

The standalone suite validates witness signatures and expiry, the interoperability
fixture, user-created event handling and packaged RBAC/ABAC models. Checks run
from source, a normal fresh wheel outside this checkout and a rebuilt sdist wheel.
Wheel runtime and policy resource bytes must match source.

Original database, checkpoint, policy lifecycle and HTTP integration tests,
fixtures and Dockerfile remain under core/acl-service as owner integration
references. That Dockerfile assumes the monorepo layout and is not a standalone
build. PostgreSQL/RLS, concurrency, container and consumer acceptance remain separate.

The main-only hosted workflow uses pinned actions, read-only contents and exact
repository credential headers. Actions remains disabled pending approved scoped
DEPENDENCY_READ_TOKEN access and hosted-worker policy. No live policy, signing
key, identity, publishing or deployment operation occurs.

## Policy administration

Creating or deleting policies requires a preexisting tenant RBAC grant for
`user:<authenticated-subject>`, resource `/acl/policies`, action `manage`.
Provision the initial administrator through a trusted owner-controlled bootstrap
path; ordinary tenant membership cannot grant this permission through the API.
