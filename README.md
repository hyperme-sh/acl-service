# acl-service

Tenant authorization for the Hypermesh control plane. This service stores
per-tenant [Casbin](https://casbin.org/) policies and evaluates them over HTTP,
and it keeps the SociACL witness, share, recovery, and keyring state those
decisions depend on. The package is `acl-service` **0.1.0**. The application
factory is `acl_service.app.create_app`. The process entry point is
`python -m acl_service.main`.

## Why

Hosts, renters, and platform admins share a tenant, and each role needs its
own permissions. Control-plane callers need one fail-closed decision for those
checks, and a store for signed witness policy, share tokens, and verified
keyring ciphertext. This service is that decision point. Lease state, ticket
signing, and the host agent live in their own repositories.

## How it works

The process is a FastAPI application. On startup it opens the PostgreSQL
database from `DATABASE_URL` (schema from the pinned
[`controlplane-db`](https://github.com/hyperme-sh/controlplane-db) migrations),
builds a `PostgresPolicyStore`, and subscribes to control-plane events.
Row-level security keeps each tenant's rows in that tenant. Authentication is a
Keycloak access token, validated through
[`auth-service`](https://github.com/hyperme-sh/auth-service) and
[`controlplane-identity`](https://github.com/hyperme-sh/controlplane-identity).
Every tenant-scoped route requires `X-Tenant-ID`, and that header must equal
the tenant claim in the token.

Casbin models ship in the package:

- RBAC (`model_rbac.conf`): subject, object, action, with `g` role links.
- ABAC (`model_abac.conf`): subject, object, action, and one extra request
  attribute (`pol`).

`POST /api/v1/acl/enforce` loads the caller's tenant rules and returns
`{"allow": true|false}`. Creating or deleting a policy requires an existing
grant for `user:<authenticated-subject>` on resource `/acl/policies`, action
`manage`. Seed that first administrator in the database. The HTTP API has no
route that promotes an ordinary member into this grant.

SociACL sits beside those rules:

- Share links store a hashed token, a predicate, an expiry, and an optional use
  count. Evaluation reserves one use before an allow or notify decision.
  Storage errors and a failed reservation deny.
- Group membership is read from the user, group, and membership rows for the
  same tenant. Caller-supplied context cannot establish membership.
- Predicates that ask for a verification level, a vouch count, a distance, a
  political tolerance, or a cross-network handle allow/block list are denied
  until a trusted same-tenant evidence source exists. Unrestricted predicates
  and a verified group membership can allow.
- Recovery routes store workflow metadata. `POST .../proof` records
  `awaiting_proof`. Proof checking and key release stay with the witness
  verifier.
- Witness policy is installed offline with
  `python -m acl_service.witness_policy_cli`. The public
  `GET /api/v1/acl/sociacl/witness-policy` route serves the signed bundle only
  when publication is configured, and it fails closed on expiry, signature, or
  revision mismatch.
- `KeyringStore` (`PostgresKeyringStore`) holds verified recovery and wrap
  ciphertext for a principal. Callers reach it through `KeyringStore` after
  they have checked the principal, history, and signatures.

Successful policy, share, and recovery writes commit in PostgreSQL, then
publish a control-plane event. The commit and the publish are separate. A
publish error is returned on the HTTP response, and the process leaves that
event unpublished. `POST /api/v1/acl/sociacl/shares` mints a new token on every
call, so repeating it after a publish error creates a second share. An
identical policy rule returns the existing row, and a recovery session with
the same idempotency key returns the existing session. A client that calls
either route again publishes the event on that later call.

Redelivery applies to `user.created.v1` consumption in
`build_user_created_consumer`. The handler inserts
`p, <user id>, user_profile, read` with `add_rule_if_absent`, then publishes
`acl.policy.updated.v1`. If the handler fails, the Postgres consumer marks
that delivery pending again (default of 5 attempts) and the Service Bus
consumer abandons the message for the broker to redeliver. The rule insert
stays one row across those deliveries. Each delivery publishes
`acl.policy.updated.v1` again.

The default bus is the PostgreSQL `controlplane_events` table. That is the
transport in the frozen install and the root image. Azure Service Bus uses the
same `controlplane.events.v1` envelope when
`AZURE_SERVICE_BUS_CONNECTION_STRING` is set, and it needs
`azure-servicebus>=7.12.0` from the `servicebus` extra of pinned
`controlplane-core` 0.1.0
(`c46bf282a8f1a605cfb8acb9beafb474c0b1b0c8`). `uv.lock` and the image install
(`uv sync --frozen` in `scripts/install-image-runtime.py`) omit that extra.
With the variable set and the package absent, `AzureServiceBusSender.start`
raises `RuntimeError` during startup. Install the package into the environment
that runs the process, `.venv` locally or `/opt/venv` in the image:

```sh
uv pip install --python .venv/bin/python 'azure-servicebus>=7.12.0'
```

| Method | Path | Who calls it |
| --- | --- | --- |
| GET | `/api/v1/health/` | Load balancer. Returns `{"status":"Ok"}`. |
| GET | `/api/v1/acl/policies` | Authenticated tenant member. |
| POST, DELETE | `/api/v1/acl/policies` | Subject with `/acl/policies` `manage`. |
| POST | `/api/v1/acl/enforce` | Control-plane services deciding an action. |
| GET | `/api/v1/acl/protected-ping` | Subject with `/acl/protected-ping` `read`. |
| POST | `/api/v1/acl/sociacl/shares` | Authenticated creator. Raw token is returned once. |
| GET | `/api/v1/acl/sociacl/shares` | Creator, or a subject with `/acl/sociacl/shares` `manage` for the whole tenant. |
| GET | `/api/v1/acl/sociacl/shares/by-token/{token}` | Anyone holding the token. Rate limited. |
| POST | `/api/v1/acl/sociacl/evaluate` | Share-token caller. A bearer token is checked when present. |
| POST | `/api/v1/acl/sociacl/recovery/sessions` | Authenticated tenant member. |
| POST | `/api/v1/acl/sociacl/recovery/sessions/{id}/proof` | Authenticated tenant member. |
| GET | `/api/v1/acl/sociacl/witness-policy` | Public when publication files are configured. Otherwise 404. |

OpenAPI is served at `/docs`.

## Practical use

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/) 0.11.26. Direct
dependencies are pinned in `pyproject.toml`:

| Package | Requirement |
| --- | --- |
| `acl-service` | 0.1.0 |
| `casbin` | >=1.36.0 |
| `casbin-sqlalchemy-adapter` | >=1.4.0 |
| `cryptography` | >=46.0.0 |
| `auth-service` | `hyperme-sh/auth-service` @ `47fc18da54f80b821029424eaac02c27b051399d` |
| `controlplane-api` | `hyperme-sh/controlplane-api` @ `82fc8c2ca21531f1a3f7a695257b3465c4a347da` |
| `controlplane-core` | `hyperme-sh/controlplane-core` @ `c46bf282a8f1a605cfb8acb9beafb474c0b1b0c8` |
| `controlplane-db` | `hyperme-sh/controlplane-db` @ `95ef61433374274f4a4fc287e15982be6357e1cc` |
| `controlplane-events` | `hyperme-sh/controlplane-events` @ `2a49f9af5f6c4dc9d6c4ddebc83c41d6331e2c87` |
| `controlplane-identity` | `hyperme-sh/controlplane-identity` @ `127d15fce7c3af8d8f8e239fb306ce88de76f02a` |
| `spanopticon-models` | `hyperme-sh/controlplane-models` @ `9a9bbb20c2e0cd41febf3233ce7a48fe17a84b04` |

Git must be able to read those repositories. Apply the `controlplane-db`
migrations before the first request. The process expects those tables to
exist when it opens `DATABASE_URL`.

```sh
uv sync --frozen
export DATABASE_URL='postgresql+psycopg://controlplane:controlplane123@127.0.0.1:5432/controlplane'
export SERVICE_NAME=acl-service
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export REFRESH_TOKEN_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export KEYCLOAK_JWKS_URL='http://127.0.0.1:8081/realms/controlplane/protocol/openid-connect/certs'
export KEYCLOAK_ISSUER='http://127.0.0.1:8081/realms/controlplane'
uv run python -m acl_service.main
```

The process listens on `0.0.0.0:8000` (`HOST` and `PORT` override that).
`ACL_RATE_LIMIT_PER_MINUTE` defaults to 240 enforce checks per tenant and user.
`ACL_SERVICE_CORS_ORIGINS` enables browser CORS when set.

A control-plane service points `ACL_SERVICE_URL` at this base URL. An empty
URL is a deny in those callers.

```sh
curl -sS -X POST 'http://127.0.0.1:8000/api/v1/acl/enforce' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H 'Content-Type: application/json' \
  -d '{"model":"rbac","sub":"user:'"$SUBJECT"'","obj":"/marketplace/listings","act":"create"}'
```

Reference tuples for that call live in
`acl_service.infrastructure.domain_policy_loader`: a marketplace seller role on
`/marketplace/listings`, an ABAC rule that binds listing management to the
seller id, and an ABAC rule that allows `/ai/inference` `invoke` only when the
extra field is `budget:<id>`.

Install or check a signed witness policy offline. `--check` does not open the
database. Installation and `--export` read `DATABASE_URL`.

```sh
python -m acl_service.witness_policy_cli \
  --policy policy.json --signature policy.sig --root-key root.pem \
  --audience hypermesh --check
```

Public delivery of an already installed policy needs all four variables, each
path absolute:

```sh
export SOCIACL_WITNESS_POLICY_PAYLOAD_FILE=/var/acl/policy.json
export SOCIACL_WITNESS_POLICY_SIGNATURE_FILE=/var/acl/policy.sig
export SOCIACL_WITNESS_POLICY_ROOT_FILE=/var/acl/root.pem
export SOCIACL_WITNESS_POLICY_AUDIENCE=hypermesh
```

The root image installs the frozen dependencies and this package, then runs as
UID 10001 with `python -I -m acl_service.main`. Pass a GitHub token that can
read the pinned repositories as a BuildKit secret.

```sh
docker build --secret id=dependency_read_token,env=DEPENDENCY_READ_TOKEN -t acl-service:local .
```

The container joins Docker's default bridge. `127.0.0.1` on that network is
the container, so the host PostgreSQL and Keycloak URLs from the local example
above do not reach those processes. Set `DATABASE_URL` and `KEYCLOAK_JWKS_URL`
to addresses the container can open. Set `KEYCLOAK_ISSUER` to the `iss` value
carried in the access tokens.

```sh
docker run --rm -p 8000:8000 \
  --add-host=host.docker.internal:host-gateway \
  -e DATABASE_URL='postgresql+psycopg://controlplane:controlplane123@host.docker.internal:5432/controlplane' \
  -e KEYCLOAK_JWKS_URL='http://host.docker.internal:8081/realms/controlplane/protocol/openid-connect/certs' \
  -e KEYCLOAK_ISSUER='http://127.0.0.1:8081/realms/controlplane' \
  -e SERVICE_NAME=acl-service \
  -e JWT_SECRET -e REFRESH_TOKEN_SECRET \
  acl-service:local
```

`host-gateway` is the host as seen from the bridge. When PostgreSQL and
Keycloak are containers on a shared user-defined network, use their DNS names
in `DATABASE_URL` and `KEYCLOAK_JWKS_URL` instead.

On a Linux daemon, `--network host` places the process on the host network
stack. The `127.0.0.1` URLs from the local example then reach PostgreSQL and
Keycloak, and the process listens on the host's port 8000.

```sh
docker run --rm --network host \
  -e DATABASE_URL -e SERVICE_NAME=acl-service \
  -e JWT_SECRET -e REFRESH_TOKEN_SECRET \
  -e KEYCLOAK_JWKS_URL -e KEYCLOAK_ISSUER \
  acl-service:local
```

## How Hypermesh uses it

Hypermesh sells a lease on a certified host. The
[plane](https://github.com/hyperme-sh/hypermesh-plane) owns classes, devices,
host certification, and lease state. The
[host agent](https://github.com/hyperme-sh/hypermesh-host) enrolls the box and
runs the lease. [hypermesh-ticket](https://github.com/hyperme-sh/hypermesh-ticket)
signs the hm1 lease ticket the gateway checks. This service answers whether
the caller may take the action.

Hosts and renters are users. A host shop is an organization inside the
marketplace tenant. The plane and the other control-plane services built on
[`controlplane-api`](https://github.com/hyperme-sh/controlplane-api) set
`ACL_SERVICE_URL` and `POST /api/v1/acl/enforce` with the caller's bearer token
and `X-Tenant-ID` before they create or administer tenant resources. The same
call authorizes marketplace listing actions and budget-scoped inference.

When [`user-service`](https://github.com/hyperme-sh/user-service) publishes
`user.created.v1`, this service consumes it (group
`acl-service-controlplane-events`, client `acl-service-user-events`) and
inserts `p, <user id>, user_profile, read` if that rule is absent. It then
publishes `acl.policy.updated.v1`. Policy create and delete publish the same
event type with operation `added` or `removed`.

Share and recovery traffic stays on this service. A tenant member creates a
share; a later caller presents the token to `by-token` or `evaluate`. Those
routes emit `sociacl.share.created.v1`, `sociacl.share.resolved.v1`,
`sociacl.access.decided.v1`, and `sociacl.recovery.session.started.v1`.
Operators install the witness policy with the CLI. Hosts and other verifiers
fetch `GET /api/v1/acl/sociacl/witness-policy` when publication is turned on.
Keyring writes stay on the storage API used by that witness path. The gateway
publishes this HTTP API. The service listens on port 8000.

## Develop and test

```sh
uv sync --frozen
bash scripts/check-package.sh
```

`scripts/check-package.sh` runs the `tests/` suite from source, from a fresh
wheel, and from a rebuilt sdist. Docker is required. The suite starts
PostgreSQL 17 and applies the pinned database migrations. A missing Docker
daemon or a failed migration fails the run. `tests/` is the CI entry point.
`core/acl-service/tests` is retained history.

`bash scripts/check-package.sh --fixtures` installs the verified dependency
wheels in `tests_artifacts/` and runs the same consumer checks without Git
credentials. `bash scripts/check-postgres.sh` installs the package and runs
`integration/` against a disposable PostgreSQL 16 container.
`bash scripts/check-image.sh acl-service:local` compares image bytes with
`src/acl_service` and exercises the HTTP routes in a read-only container with
networking disabled.

Release mechanics, artifact retention, and the stable tag path are in
[Releasing](docs/releasing.md). Runtime archive staging is in
[Preparing a retained ACL runtime](docs/runtime-preparation.md).

## Release and versioning

The package version is **0.1.0**. A push to `main` validates that commit and
keeps the wheel and sdist as Actions artifacts. A `vMAJOR.MINOR.PATCH` tag on
that tested commit publishes the GitHub Release from those exact files.
Details, the immutable candidate, and qualification versus a stable baseline
are in [Releasing](docs/releasing.md). Compatibility rules for admission are
in [Release compatibility](docs/release-policy.md).

## License

First-party code is [Apache-2.0](LICENSE). Dependency packages keep their own
licenses.
