# acl-service

`MediaSource` in the fixed admission bundle implements direct private-media
authorization over the existing enrolled identity database and its independent
freshness database. Objects start empty under an operator-verified exclusive
admission grant; there is no history import or implicit identity enrollment.
It retains signed private grants and cancellations, freezes authenticated
same-revision conflicts, and authenticates pending epoch history before retaining
service first-seen times. The direct ACL projection uses each signed monotonic
grant revision as its logical HAM value; owners sign that exact snapshot.
Group snapshots are refused by this source.

Delivery re-resolves all enrolled keys and complete history in one protected
view, verifies the current private grant, latest settled epoch and bounded signed
status, and binds the private wrap digest to the current recipient encryption
key. After storage fetch, it repeats those checks and atomically commits the
same fence and identity/epoch floors. Any intervening identity, policy, grant,
epoch or wrap change refuses. Independent media checkpoints reject restored old
databases. Cancellation stops a pending worker from committing and holds its
source slot until that worker exits.

There are at most 64 objects per tenant, 64 live grant records plus 64 reserved
cancellation records per object, 64 authenticated epoch records, and 64 enrolled
identities. No history is pruned to make room: exhaustion refuses new writes
while reserving cancellation capacity. Policies and mutations have separate
byte caps. This source is not automatically provisioned or bound to HTTP callers;
deployment and authenticated consumer wiring must supply explicit existing
tenant/subject mappings. Tests with substituted identity/native providers are
marked not production-ready. No new credentials or source grants are installed.

`PrivateWrapStore` reads and creates private immutable reader-wrap records through
the configured Spanopticon tenant's `media` record namespace. Names are opaque
64-character lowercase hexadecimal identifiers; never derive them by exposing
recipient or object labels. Reads require an independently retained SHA-256
revision and verify the returned bytes. Payloads are capped at 64 KiB. Requests
use tenant-bound credentials, refuse redirects and compression, and have bounded
deadlines and connection capacity. Creates use `If-None-Match: *`; conflicts and
lost responses never cause an automatic retry or overwrite.
The async adapter applies a total two-second timeout across response headers,
streamed bytes and response cleanup, including with an injected client. Each
request explicitly disables redirects. Use and close the client on its event
loop; CI exercises slow headers and a body that trickles below the chunk size.

This storage adapter is not an authorization endpoint. The owner source must
authenticate the current reader, select the current epoch, retain the opaque
record and digest privately, and revalidate its authorization fence after fetch
before returning any material. Nothing initializes the adapter or publishes a
route by default. Use the s3r.ch Spanopticon tenant, not direct Blob credentials.

`deliver_private_wrap` enforces that ordering: it obtains an immutable permit from
the mandatory owner authority, fetches the exact digest, then asks that authority
to atomically revalidate and commit the same fence before returning bytes. The
permit binds tenant, reader, object, epoch/revision, recipient key and private
record. Expiry, cancellation, changed authority, wrong tenant or corrupt bytes
refuse. The owner authority must cover all relevant history and policy changes
and commit rollback floors in its transaction; this module installs no permissive
authority and enables no endpoint. Its isolated units test the fetch/commit order
and refusal boundaries. Protected-source and HTTP route wiring remain under #81.
The complete async delivery operation has a three-second deadline, including
both authority calls, so an unavailable owner source cannot hold a request forever.

`POST /api/v1/acl/sociacl/media/read-wrap` accepts only `{"object":"..."}`
in an uncompressed JSON body capped at 2 KiB. It requires authenticated matching
tenant claims, `acl:media:read`, and an explicit server-side tenant/subject binding
to an enrolled reader, owner authority and tenant store. It never accepts reader,
epoch, revision, storage location or authorization fields from that request.
The service rate limit applies before body reads. Each configured subject has
one body-upload slot with a one-second deadline. Only validated bodies reserve
backend capacity: one operation per tenant and two globally. Slow uploads cannot
occupy another tenant's backend slots. Slot maps contain only configured bindings;
requests cannot grow them. The whole request has a four-second deadline. A successful response contains
`context` (`object`, `epoch`, `revisionId`), `readerEpub`, `expiresAt` (Unix seconds)
and `wrapBase64`, all from the same committed delivery decision. Storage record
names, owner fences and provider addresses are omitted. Responses use private,
no-store caching. Consumers must use this authenticated current context and their
matching enrolled encryption key when opening the existing SociACL reader wrap.
They must not reuse an expired response as current authorization.

The application factory accepts optional `private_wrap_bindings`; the default is
unavailable, with no environment-based activation or permissive authority.
Concrete protected-source construction, owner enrollment and deployment wiring
remain under #81. This transport does not provision any of them.

The image carries the shared SociACL Rust epoch-status verifier, built from the
exact source revision in `admission/sociacl-native.rev`. The packaged
`EpochStatusVerifier` loads only `/opt/acl-admission/libsociacl.so` and checks
bounded raw proof/context documents through its C interface. The native parser
rejects duplicate fields, positional arrays and malformed values. Its clock and
policy inputs use milliseconds and cannot wrap unsigned C integers.

`PrivateGrantVerifier.matches_grant` verifies the existing confidential
`SignedGrantPayload` transcript against exact protected context, including
owner/reader, grant revision, epoch and item ciphertext digest. It also matches
signed cancellations; a match is not current permission. Public `SeeGrant` rows
cannot replace this private grant or supply its monotonic revision. The source
must still enforce current Check, enrollment, status, settlement and rollback
custody before delivery. Both raw JSON documents are capped at 64 KiB, preserved
for strict native parsing, and never accepted as caller-provided authority.

`matches_status` means only that signature, freshness and exact context match.
A matching cancellation also returns true. The caller must independently supply
the current enrolled owner key, epoch, grant and graph state; a request cannot
choose that context. Current Check, rollback custody and confidential reader-wrap
delivery remain required under #81. No route or source binding activates media
through this adapter. Missing libraries/symbols fail at construction, with no
structural or permissive fallback. CI checks TypeScript-signed proofs against the
native Rust implementation in an isolated container, plus package unit coverage.

`EpochManifestVerifier.matches_manifest` also authenticates the existing signed
manifest and its ACL snapshot through the Rust reference. It bounds each raw
document to 64 KiB and preserves duplicate-field refusal. The expected owner key,
object, epoch and revision must come from protected state. A valid old manifest
can match: this is not current-history selection, settlement or Check. CI covers
cross-language signatures, snapshot tampering and malformed representations.

`SettledEpochVerifier.matches_settled` matches the latest settled reference-chain
winner from a bounded protected history document. The source must supply complete
history, authenticated signing-key bindings, current ACL, first-seen times, clock,
group configuration, retained anchor and epoch floor. Client JSON is not a trusted
input to this adapter. Pending successors refuse without falling back to old keys.
The selection still requires current Check, enrolled recipients, rollback custody
and a delivery fence before any private wrap can leave the service.

The image also carries an operator-only `DelegationSource` in its admission
bundle. It provisions a new exclusive scope for one canonical HTTPS audience,
using the same tenant-bound identity store and independent rollback checkpoint
as statement admission. It retains owner-signed delegations and cancellations,
including expired records, and verifies them with the published SociACL helpers.
It never imports an existing delegation collection or treats a statement scope
as delegation history. At most 64 delegations per owner and 512 per scope reserve
space for one permanent cancellation of every delegation. This journal does not
prove agent possession or grant object access. Agent login must still verify
current delegation authority and challenge the agent key on every exchange.
Private HTTP transport is default-off. Set `SOCIACL_DELEGATION_BINDINGS_FILE`
to an owner-only version-1 binding file with the same tenant, subject, scope,
historyFile and freshnessFile fields described for statement bindings below.
Its scope must already be provisioned as a delegation journal. The loader never
enrolls identities or creates scopes. Authenticated callers use
`POST /api/v1/acl/sociacl/delegations/{scope}/{snapshot|append}` with separate
`acl:delegations:read` / `acl:delegations:write` scopes and an exact tenant/subject
binding. Bodies, timeouts and fences match statement transport, and both routes
share one two-worker budget. Statement permissions do not grant delegation access.
The s3r.ch consumer and deployment activation remain separate work under
FyberLabs/s3r.ch#277.

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
builds a `PostgresPolicyStore`, and accepts authenticated User event deliveries.
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
  ciphertext for a principal. The running app wires the session store only.
  The [recovery adapter inventory](docs/recovery-adapters.md) traces both
  storage paths and identifies where verified chain resolution belongs.

Policy, share and recovery mutations now commit together with their local outbox
row. Existing store commits release an inner savepoint; the owner operation makes
the final commit. An outbox failure rolls back the business change, including a
reserved share use. API responses are constructed before that owner commit.

`POST /internal/events` accepts only authenticated `user-service` deliveries of
`user.created.v1`, with a matching `Idempotency-Key`. Inbox dedupe, the default
`p, <user id>, user_profile, read` policy and `acl.policy.updated.v1` commit in one
transaction. Reusing an event ID with different facts is refused. Configure
`EVENT_PRODUCER_TOKENS_FILE` as a private JSON mapping containing `user-service`.
Missing credentials refuse deliveries. ACL no longer reads the shared event log
or selects a Service Bus sender/receiver.

Before starting the new runtime, deployment setup applies the additive event DDL:
`python -m acl_service.migrate --database-url-file /run/secrets/acl-database-url`.
Installation grants existing `controlplane` and `controlplane_app` roles read/insert
access to transport rows and update access only to the delivery marker. For a
dedicated runtime/relay role, repeat `--runtime-role ROLE` for each existing role.
It does not create roles or grant row deletion. HTTP deliveries must include the
sender's stable `occurred_at` timestamp so retries compare the same facts.
It preserves the existing business tables and adds forced-RLS inbox/outbox tables
plus the service tenant registry used by the standard owner HTTP relay. Configure
that relay against this owner's database; independently deployed peers retain the
same event envelope. Rolling back the runtime does not require deleting tables.

Policy create/delete IDs include the policy row incarnation and operation. Share
creation and recovery creation use their business row IDs; recovery retries retain
the original `pending` creation fact even after the returned session advances.
Resolutions and access decisions represent new operations; a retry of an event
write inside the transaction reuses its operation ID. This does not add a new
HTTP idempotency contract to share creation or access evaluation.

| Method | Path | Who calls it |
| --- | --- | --- |
| POST | `/internal/events` | Authenticated User owner relay; atomic inbox and default policy. |
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
`user.created.v1`, this service consumes its HTTP delivery and
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

## Configured startup grants

The default-disabled startup endpoint is POST `/api/v1/internal/startup/reconcile`.
It requires `STARTUP_IDENTITY_ENABLED=1`, a private `STARTUP_IDENTITY_CONFIG_FILE`,
`ACL_STARTUP_TOKEN`, and the configuration's `mapping_sha256`. It reads the
already-bound person from `STARTUP_AUTH_URL` using `AUTH_STARTUP_READ_TOKEN`.
No body-supplied identity, email, membership or administrator flag is accepted.

The existing tenant policy store commits the mapping and eight explicit grants
in one transaction under a tenant lock: separate Spanopticon/hyperme.sh platform
admin rows and owner/admin rows for each organization ID. SEA remains the
canonical subject; one explicit broker-subject alias enables the same login.
Keycloak administration is never an ACL policy. No wildcard or cross-tenant
rule is created. Replays preserve unrelated rows; conflicting mappings and
removed committed grants fail closed. Unit contracts verify exact resource
separation. The existing scheduled PostgreSQL storage harness covers concurrent
replay and rollback/retry; registration belongs to FyberLabs/infra#923.

The [signed statement source](docs/statement-source.md) supplies the optional,
explicitly provisioned s3r.ch graph snapshot and atomic append API.

## Private statement source startup

`SOCIACL_STATEMENT_BINDINGS_FILE` enables the private statement source routes.
Without it, the source remains unavailable. Invalid configuration aborts startup;
it never falls back to another tenant, graph, or storage backend.

The file is a UTF-8 JSON object (at most 64 KiB):

```json
{"version":1,"bindings":[{"tenant":"a5ed86d0-cb50-4404-a5ac-410aab086a82","subject":"s3rch-service","scope":"forum","historyFile":"/var/lib/acl-private/history.db","freshnessFile":"/var/lib/acl-checkpoint/freshness.db"}]}
```

Use the authenticated subject from the exchanged service key, with dedicated
`acl:statements:read` and `acl:statements:write` scopes. Each binding fixes its
tenant, subject, and graph scope. Multiple subjects may share the same tenant's
store; conflicting tenant or checkpoint assignments are rejected.

Mount already-provisioned history and independent freshness databases, with
owner-only file permissions (`0600`) and protected parent directories, readable
and writable by the service UID 10001. The configuration must also be owner-only;
all configured paths must be canonical absolute paths without symlinks. Keep the
freshness store under its independent operational custody. The startup loader
checks that the tenant, graph, identity checkpoint and graph checkpoint already
exist. It neither creates missing stores nor enrolls identities or grants graph
ownership. Use the existing operator admission path to establish a new exclusive
graph; do not import an arbitrary Gun graph or claim it is complete.

The loader uses only the verifier shipped at `/opt/acl-admission` in the service
image. Signature checks and current-history/checkpoint fences remain enforced by
the source on every operation. Package-only environments without that bundle
cannot activate this setting. Configuration changes require a service restart.
