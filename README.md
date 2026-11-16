# acl-service

`POST /api/v1/acl/sociacl/media/groups/item-view` accepts exactly
`{object, predicate, set}` under an existing `SOCIACL_GROUP_WRAP_FILE` subject
binding and `acl:media:write`. The owner comes from that authenticated binding.
The protected source verifies the owned item's current direct access and the
owner's current group-key access in one transaction. It returns the item and
group epoch context, owner public key, fence and short expiry for browser
preparation. This read does not grant group access, publish wraps, or change
storage. It shares the group routes' bounded input, capacity, timeout,
disconnect cancellation and private, no-store responses. Missing configuration
keeps it disabled; clients cannot supply an owner or evaluation time.

The internal `group_item_authority_view` prepares retained item edges against
current independent group membership in one protected read transaction. It
ignores membership rows and membership cancellations copied into an older
media document. Native projection first selects the current owner-signed
object-set edge without group membership rows. Only a live selected edge reads
its independent group journal, and the caller must be an explicit current
member before its rows enter the returned projection. Owning an item or a set
does not bypass that requirement. Detached and superseded groups disclose no
membership. Missing selected groups or invalid current group policy refuse;
there is no fallback to copied members. Its fence covers the media source and
the selected group. It does not change retained rows, admit a binding, or grant
delivery. `POST /api/v1/acl/sociacl/media/groups/item-authority-view`
exposes this preparation for a configured authenticated subject with
`acl:media:write`. Its only request field is `{object}`: the source selects the
current group, and the caller cannot supply a member, owner, set or evaluation
time. It uses the group-wrap route's private response headers, 2 KiB request
limit, rate/capacity bounds and disconnect cancellation. Missing explicit
current membership refuses before group members are returned.

`SOCIACL_MEDIA_BINDINGS_FILE` enables private wrap delivery only for explicit
authenticated tenant/subject pairs. Its private JSON file has `version: 1` and
at most 64 `bindings`, each containing `tenant`, `subject`, `reader` (the enrolled
SEA principal), `historyFile`, `freshnessFile`, `storageOrigin`, and
`storageKeyFile`. All paths are absolute private regular files. The storage key
file contains the exact credential, without a trailing newline. Each tenant
uses one protected history/checkpoint pair and one Spanopticon storage origin
and credential, shared by its reader bindings. The gateway/auth-service must
authenticate the subject and grant `acl:media:read`; request JSON cannot choose
the reader. Never bind a shared browser service credential to arbitrary users.
Missing configuration disables delivery. Invalid configuration fails startup.
Loading does not create source grants, enroll readers, or initialize databases;
the tenant's media sources and independent checkpoints must already exist.

The same fixed subject binding may receive `acl:media:write` for its own media
objects. `POST /api/v1/acl/sociacl/media/owner/catalog` takes `{page}` (integer
0 through 15). It returns `{at, objects, nextPage}`, with at most four IDs per
page. Canonical owner prefixes narrow candidates; native identity verification
against current protected history and policy must still confirm each owner.
Other owners' rows do not affect page positions. The sixteen-page envelope is
fixed regardless of occupancy; `nextPage` is null only on page 15. Empty pages
are valid. No recipient, storage address, digest or key is returned. Catalog
reads do not create a grant or replace authorization on subsequent operations.
Concurrent admissions may shift pages: clients should deduplicate IDs and
refresh the catalog instead of treating it as a completeness proof.

`POST /api/v1/acl/sociacl/media/owner/view` takes only `{object}` and
returns the current evaluation `at`, write `fence`, direct ACL snapshot and
bindings for the owner and that object's admitted recipients. It does not list
unrelated enrolled identities. `POST /api/v1/acl/sociacl/media/owner/mutate` takes
`{object, at, fence, operation, payload}`; supported operations are `grant`,
`epoch`, `status` and `wrap`. The writer always comes from the authenticated
subject's configured binding. Owner signatures and current identity/policy checks
remain mandatory inside the protected source. A stale evaluation or fence returns
409: refresh and reconcile before signing a new mutation; no automatic retry.
`POST /api/v1/acl/sociacl/media/owner/status-view` takes `{object, reader}`
and returns `{at, fence, ownerPub, status}` for an existing live recipient grant.
The status draft contains the native-selected settled epoch, current grant
revision and object version, the service clock, and a validity bounded by the
policy and grant (at most 60 seconds). Pending epochs and changed owner signatures
refuse. The owner signs this draft client-side and submits it through `mutate`
with operation `status`; the source still verifies the signature and exact current
fence. Reading a draft does not update history, grant access or create a signature.

`POST /api/v1/acl/sociacl/media/owner/cancel-view` takes `{object, reader}`
and returns `{at, fence, ownerPub, grant}`. The grant draft copies the protected
latest grant, sets `stated` to zero and increments its safe integer revision.
It is read-only: the owner must sign and submit through `mutate` with operation
`grant`. Current owner key rotation does not require possession of the previous
private key to cancel an already admitted grant. Missing, already cancelled,
frozen or revision-exhausted grants refuse; policy and independent checkpoint
checks still apply. Expired grant dates are preserved, never extended.

`POST /api/v1/acl/sociacl/media/owner/publish-wrap` takes
`{object, at, fence, metadata, wrapBase64}`. The canonical base64 encodes at most
64 KiB of opaque encrypted wrap bytes. Metadata uses the existing `wrap` shape;
its `record` and `digest` must both equal the bytes' SHA-256. The source checks
the current owner and signed recipient grant, then durably reserves capacity
before storage access. A short-lived write permit binds that reservation and
all current authority. After storage creation, a second protected check commits
the metadata; intervening authority changes refuse the commit.

Each object retains at most 128 reservations, including failed or cancelled
uploads. Reservations are never pruned or refunded, bounding retained uploads
to 8 MiB per object and 512 MiB per tenant's 64 objects. Retry requires a fresh
owner view: an identical reservation can reconcile a create conflict by reading
and verifying the exact existing bytes. Different bytes are never overwritten.
An already committed identical wrap does not advance the object version again.
These routes do not provision objects, replace policy, create credentials, or
initialize storage.

`MediaSource` in the fixed admission bundle implements direct private-media
authorization over the existing enrolled identity database and its independent
freshness database. Objects start empty under an operator-verified exclusive
admission grant; there is no history import or implicit identity enrollment.
It retains signed private grants and cancellations, freezes authenticated
same-revision conflicts, and authenticates pending epoch history before retaining
service first-seen times. The direct ACL projection preserves the signed monotonic
grant revision and uses SociACL's required zero HAM value for direct grants;
owners sign that exact snapshot.
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
deadlines and connection capacity. Creates use `If-None-Match: *`; lost responses never cause an automatic
retry or overwrite. Publication reconciles an explicit create conflict only by
reading and verifying identical bytes under the reserved digest.
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

`MediaSource.consume_allocation` is the internal atomic consumption boundary for
new media allocations. Its trusted adapter supplies a configured signature
verifier bound to issuer, source, tenant and policy; request JSON cannot supply
that callable or choose those bindings. The method independently verifies the
canonical signed ownership record against current protected SEA history, checks
its digest and the configured policy digest, and commits the allocation ID,
empty media state and independent checkpoints together. An identical retry
reconciles without replacing state. Conflicting IDs, existing objects, partial
restores, expired authority and cancellation refuse. Ownership and policy digests
are SHA-256 of sorted compact JSON with ASCII escaping, including the ownership
signature. There is no transport route or issuer configuration enabled by this
internal method; authenticated issuance and runtime wiring remain required.

`SOCIACL_MEDIA_ALLOCATION_FILE` separately enables
`POST /api/v1/acl/sociacl/media/allocate` for configured tenant/subject bindings
with `acl:media:write`. The body is only the canonical ownership record
`{object, owner, issuedAt, sig}`. Neither issuer, protected source, policy nor a
signing key comes from the browser. The source checks current SEA history before
signing a 30-second request, exchanges it once through the tenant Storage gateway,
verifies the signed grant, then rechecks current ownership during atomic
consumption. Identical requests reconcile; conflicting or uncertain results must
be refreshed rather than implicitly retried. Disconnects and deadlines cancel
pending work. This does not create reader grants or publish media.

The private version-1 JSON file has at most 64 `bindings`. Each contains the usual
`tenant`, `subject`, `reader`, `historyFile`, `freshnessFile`, `storageOrigin`, and
`storageKeyFile`, plus `issuer`, `source`, `policyFile`, `policyUntil`, `keyId`,
`sourceKeyFile`, and `issuerKeys`. Issuer and source are configured UUIDs.
`policyFile` is private JSON containing exactly `jwks`, `policy`, and `pinnedIss`;
its canonical digest must match the Storage issuer configuration. The source key
file contains a canonical unpadded base64url 32-byte Ed25519 seed with no newline.
`issuerKeys` maps configured issuer key IDs to similarly encoded public keys.
The source key must differ from every issuer key. Files are private, distinct and
tenant-bound; bindings for the same tenant must agree on their source and policy.
The gateway credential needs `storage:allocations:issue`; it is not itself proof
of current SEA ownership.

The history and independent checkpoint databases must already be provisioned.
An explicitly configured allocation source may initially contain zero media
objects; ordinary private-wrap delivery still requires provisioned objects unless it shares
the exact configured allocation authority, history/checkpoint files and Storage
origin. In that case it reuses that authority and can serve the first object
without a restart. Existing checks on every delivery remain unchanged.
Loading allocation settings never enrolls identities, creates credentials or
bootstraps the Storage registry. Missing configuration disables this route and
invalid configuration fails startup. Operator staging and registry initialization
remain required before deployment activation.

The allocation verifier and source signer under `acl_service/allocation_protocol`
are byte-identical Core wire modules. CI compares both files with the exact
reviewed Core source revision recorded in `preparation.yml`. They import only
standard-library and cryptography code, avoiding a forced upgrade of the older
shared service dependency set. Protocol changes must update the pinned source
and both consumer copies together; CI refuses drift. Core remains the protocol
owner and tests the durable issuer independently. Native ACL CI tests the real
current ownership/signing/verification/consumption boundary with fixture keys.

### Initial upload reconciliation

`POST /api/v1/acl/sociacl/media/owner/upload-state` takes exactly
`object`, `operation` (`grant`, `epoch`, or `wrap`), and the original `payload`.
It returns only `at` and `state`: `absent`, `applied`, or `conflict`.
This is a private, read-only probe for the initial owner grant, first epoch,
and owner wrap, under the existing fixed subject, tenant and `acl:media:write`
binding. Native current ownership and the independent checkpoint remain required.
A wrap probe additionally checks its current grant and encryption-key binding.

A browser keeps its original signed intent after an uncertain response and probes
before deciding what to do next. `applied` confirms retained matching state; it
never means the epoch has settled or reader delivery is permitted. `absent` is
not a write permit: another write still needs a fresh view/fence and all ordinary
signature checks. Conflicting or superseded state requires explicit reconciliation.
No operation automatically retries, creates an object, or releases quota.

### PostgreSQL protected source storage

`PostgresHistoryStore` provides serialized history transactions over separate
history and checkpoint schemas in ACL's PostgreSQL database. The configured
canonical tenant and source UUID must match both pre-existing markers. Runtime
construction performs no DDL or repair. Missing scopes, markers, or authority
snapshots refuse; every transaction checks the independent authority digest.
History admission, ciphertext generation and media allocations share the source
row lock. Contention is bounded and requires a fresh caller fence, with no replay.

The explicit `provision_empty_media_source` operator function creates both new
schemas atomically and refuses either existing schema, including an empty one.
It creates no identities, private keys, media objects, policy or grants. Existing
owner admission still requires verified native history and the separately tracked
wallet-to-SEA resolution. This is not an import or runtime enrollment API.

Use separate restore scopes and restricted runtime database roles: history must
never be restored together with its checkpoint authority. A full rollback of
both scopes is outside the independent-checkpoint guarantee. Keep schema creation
privilege with the provisioning role. PostgreSQL binding-file routing and the
operator's owner-admission entrypoint remain tracked by #103; existing runtime
binding files retain their current format until that work lands. No service or
storage activation is enabled by this adapter.

Private media and allocation binding envelopes also accept `version: 2`.
Each row replaces `historyFile` and `freshnessFile` with `postgresFile`, an
absolute private regular file. All other subject, reader, storage and allocation
fields retain their existing meaning. Version 1 remains compatible.

The private PostgreSQL file contains exactly `version: 1`, `databaseUrl`
(an explicit `postgresql+psycopg` address), `historySchema`, `checkpointSchema`,
`tenant`, and `source`. Schema identifiers begin with `acl_` and contain only
lowercase letters, digits and underscores. Tenant/source UUIDs must be canonical
and match the provisioned source. The database address is secret configuration;
it is neither returned over HTTP nor printed in configuration errors.

The loader reads each tenant's PostgreSQL configuration once. Allocation fixes
the same source UUID as its issuer contract. Delivery can reuse an empty source
only when allocation already binds the identical database address, schemas,
tenant, source and storage origin. All checks precede storage-client creation.
Runtime configuration never invokes provisioning or creates an owner; missing
configuration keeps the feature disabled, while invalid configuration refuses
startup. Verified existing owner admission and operator provisioning remain
open work under #103 and s3r.ch #440.

## Private media deletion preparation

The protected source now supports a read-only `deletion_view` and a synchronous
`delete` operation for a trusted adapter. There is no public route or provider
cleanup worker yet. The view binds tenant, stable owner, object version, current
write fence and a validity window to the owner signing key. The native SociACL
verifier checks the separate deletion transcript; unshare is not deletion.

A first accepted command checkpoints a permanent deletion marker and sets the
policy deadline to zero, so existing readers also refuse the object. Reads,
writes, pending delivery commits, reprovisioning and policy restoration refuse.
The same authenticated owner's exact accepted proof can be retried after its
original time expires; only the original command identifier is returned, with
no new mutation. A changed proof or owner refuses. Primary-only rollback cannot
remove the independent checkpoint.

This does not free quota or claim ciphertext cleanup. The future cleanup worker
must account for writes already in flight, delete all reserved wraps and stored
ciphertext, and only then release quota once without erasing the tombstone or
allowing reuse of the object identifier. No activation or operator provisioning
is performed by these primitives.

The protected media source exposes `prepare_retirement_request` to a trusted
signer adapter. It reads the accepted owner deletion, verifies its independent
checkpoint and the consumed allocation checkpoint, and supplies only the stored
command with a fresh short transport window. Missing deletion, a different
owner, unallocated legacy objects, rollback, cancellation and invalid signer
output all refuse. It creates no owner consent, changes no deletion state and
releases no quota. Runtime route/client binding remains disabled until the
storage retirement consumer is wired.

The subject-bound media owner API accepts `delete-view` to obtain a current
owner deletion transcript, and `delete` to submit the owner's SociACL signature.
Both require the existing fixed subject/tenant binding and `acl:media:write`.
The browser cannot choose an owner, source or policy. A successful deletion
response reports accepted consent and `cleanup: pending`; it does not claim
provider removal or quota release. The permanent source tombstone immediately
blocks further delivery and writes. Storage cleanup is a separate retryable step.


Owner cleanup recovery uses `POST /api/v1/acl/sociacl/media/owner/cleanup-catalog`
with only `{page}` (0 through 15). It returns `{at, objects, nextPage}`;
each item is `{object, command}` for an accepted owner deletion whose storage
completion has not been checkpointed. Pages contain at most four items, including
empty pages, and retain the existing fixed sixteen-page envelope. Accepted
commands remain available after delivery-policy expiry. The authenticated
subject still supplies the owner; callers cannot select another owner.
The configured cleanup adapter records completion only after the storage client
confirms the same permanent command. Lost acknowledgements leave the command
available for explicit retry. Completion does not erase the permanent tombstone
or reclaim protected-source capacity; that requires separate indexed accounting.


Media delivery configuration version 3 uses the same PostgreSQL binding fields
as version 2 and explicitly selects allocation-bound reader wraps. Version 1
and 2 retain their existing record-store behavior. The new adapter binds the
protected read/write permit's object before storage access and requires the
record name to equal the retained digest. Uploads derive the owner from the
canonical object ID, accept only matching immutable acknowledgements, and use
`/api/v1/storage/media/payloads/{object}/wrap/{digest}`. The storage credential
needs separate payload read/write permissions; deletion remains a distinct
permission and operation. Source authorization and post-storage commit checks
remain mandatory. Selecting version 3 requires the dedicated registry/provider
data and scopes to be staged first; there is no fallback, import or activation.


`POST /api/v1/acl/sociacl/media/owner/registration` takes `{object, record}`
and confirms a signed ownership record against the authenticated owner, current
native protected history, active media policy and matching allocation anchors.
It returns `{accepted:true}` only after that read-only transaction completes.
It does not allocate an object, store another ownership copy, extend policy or
change grants. This lets allocated-storage consumers replace their legacy
registration index while keeping signature verification in the protected source.

### Explicit active media capacity upgrade

Private PostgreSQL source settings version 2 select an independently retained
active-object index. Version 1 remains unchanged. Before selecting version 2,
an operator explicitly calls `install_active_media_index` from
`acl_service.infrastructure.media_active_index` with the existing database URL,
history/checkpoint schemas, tenant and source. It verifies every old source
against its retained checkpoint (at most 64), installs the index once, and
advances both source markers atomically. Old source processes then refuse all
transactions; restart all consumers with the same version 2 settings. Runtime
construction never creates or repairs this index.

Pending deletions still consume capacity. Only confirmed storage cleanup removes
an active entry; permanent source documents and checkpoints remain to prevent
reuse. Owner pages enumerate at most 64 active entries, so completed tombstones
do not permanently exhaust capacity or hide later objects. Missing primary rows
remain represented independently and cause refusal. This does not activate a
provider, install anything in a running tenant, or import existing objects.

### Protected next-epoch context

`POST /acl/sociacl/media/owner/epoch-view` accepts only `{object}` under the
existing fixed owner binding and write scope. It returns the current snapshot,
write fence, owner key, named recipient bindings and the finalization ID/epoch
selected by the native settled-history verifier. Unrelated enrolled identities
are omitted. Unsettled history, exhausted epoch numbers and foreign owners are
refused; older adapters without this operation return unavailable.

This read-only preparation does not change grants, publish wraps or advance an
epoch. Subsequent owner signatures still require the current write fence. The
browser must preserve its intended signed changes across interrupted publication;
this endpoint alone does not implement sharing or recovery.

### Current-reader media catalog

`POST /acl/sociacl/media/catalog` accepts only a page number (0–15) and uses
the configured authenticated reader with `acl:media:read`. Each request examines
at most 64 source objects and paginates four authorized entries only after the
current authorization filter. It returns only non-owned objects satisfying the
current grant, status, settled epoch and wrap checks. Missing or mismatched
primary checkpoints refuse the page. Hidden objects disclose no IDs or total
count: page traversal is fixed through page 15. Listing never reads storage or
grants delivery; opening an item must perform the existing current read check.
Older source adapters without this optional operation return unavailable.

### First owner of a new s3r.ch media source

`admission/first_media_owner.py` provides the explicit operator-only
`admit_first_media_owner` entry point. This starts a fresh ACL journal for an
existing SEA key; it does not import prior ACL history or generate an identity.
The trusted resolver must uniquely resolve wallet
`0x4C8d36f87287e75D3D84F1aeD72655ecCbC7A1A7` under Infra #1261 to the declared
principal. Missing, ambiguous or changed resolution refuses admission. Public
wallet-link exports are not a substitute for that resolver.

The existing key signs the normal enrollment transcript using the authority
`s3rch-first-media-owner-v1:<tenant>:<source>:<lowercase-wallet>`, a 32-byte lowercase hexadecimal nonce and an expiry at most
60 seconds away. Native verification authenticates its genesis encryption-key
binding and signature. Tenant and source must match the already provisioned
PostgreSQL store. The store locks both source markers, verifies the independent
checkpoint and refuses any prior history, ciphertext, media or allocation rows.
It inserts exactly one owner with empty history and initial independent
ciphertext counters in one transaction, rechecking resolution before commit.
Any replay or competing first admission refuses; a failed commit leaves no rows.

No runtime loader or HTTP route calls this entry point. Installation and
activation remain off until Infra #1261 supplies the unique resolution and the
controlled provisioning inputs. No additional reader or primary-member authority
is installed. The existing generic enrollment path retains its separate contract.

### Protected owner share preparation

`POST /acl/sociacl/media/owner/share-view` accepts only `{object, reader}`.
The fixed owner must currently qualify for private delivery, including a fresh
signed status and settled epoch. The target must already be enrolled; this
operation cannot create a reader or accept caller-supplied identity bindings.
It returns unsigned next-epoch grant drafts for the target and every unexpired
recipient, plus the planned snapshot, parent finalization, current write fence
and only those recipients' current bindings. Future start times are preserved;
expired or cancelled targets require a new revision. Every retained recipient
proof must match the current owner key and ciphertext digest. Policy expiry,
revision exhaustion, frozen recipients and retained-history limits refuse plans.

This is read-only preparation. No grant, epoch or wrap is published. The browser
must obtain the owner's current encrypted-key material, preserve the exact signed
intent in protected recovery storage, and reconcile interrupted publication.
Until the resulting epoch settles and fresh statuses/wraps are accepted, the
plan itself grants no access. Group expansion and the complete sharing UI remain
separate work.

### Sharing recovery comparison

`POST /api/v1/acl/sociacl/media/owner/share-state` accepts
`{object, operation, payload}` and returns `{at, state}` for the fixed owner.
It compares retained next-epoch grants, epoch pairs and reader wraps without
changing access. Exact signed values are applied; the immediate missing revision
is absent; superseding or competing state is conflict. The initial-upload
endpoint retains its initial-only scope. An absent result is not permission to
write: ordinary fenced mutation and native signature checks still apply.

`share-check` takes the same fixed-owner input and adds the protected write
`fence` to the comparison result. Clients submit an absent intent using that
exact `at` and `fence`, without obtaining a replacement view. An intervening
change then refuses at the mutation boundary rather than converting a stale
plan into a conflicting grant. `share-state` keeps its existing response shape.

`unshare-view` prepares the same read-only next-epoch plan while cancelling the
selected recipient and renewing the remaining unexpired readers. The cancelled
reader receives no new wrap binding; its dates are preserved. The owner must
capture current key material and save the full plan before publishing the
cancellation. Sharing reconciliation also recognizes exact cancellation intents.
This lets removal resume the remaining readers' epoch instead of leaving only a
cancellation with an unmatched current snapshot.

The internal history verifier accepts a bounded `groupGraph` projection for one
media object and one named group/circle. It consumes canonical signed ownership,
membership, object-set and cancellation rows through the published `sociacl/group`
contract. Both membership assents and current authenticated histories are required;
the owner shortcut is not returned as group membership. The result is read-only
routing input, not a media grant, key wrap, status or delivery permit. No HTTP
endpoint or group-media activation is introduced by this projection. Protected
storage, epoch snapshot and delivery integration remain under issue #126.


The internal media source can retain signed group rows with `append_group` and
return an owner-only `group_view`. These use the existing PostgreSQL-backed media
journal, independent checkpoint and current identity fence. Appends preserve
cancellations and revalidate all retained signatures; limits are eight scopes per
object, 1024 rows per scope, 64 rows per append and 512 KiB across all group
scopes. Documents with group rows reserve space for every remaining direct-grant
cancellation slot and the deletion tombstone, including on later ordinary writes. Existing direct-grant delivery
is unchanged. These methods do not issue group grants,
epochs or wraps; those consumers remain under #126.


Group projection also returns detached canonical `snapshot` material from the
shared SociACL implementation. Membership and object-set edges keep separate HAM
values and removal states; an absent object-set edge returns null. This prepares
epoch construction and does not activate group delivery. The owner-only
`group_object_view` reads all retained scopes in one protected transaction and
uses SociACL's merge rules to select the current object-set edge. A losing scope
cannot supply members, and cancellation of the winning scope does not fall back
to an older group. Per-scope inspection alone is not a current group grant.
The internal `groupObjectGraph` verifier input is bounded to eight scopes and
1 MiB; retained source rows also keep their stricter aggregate journal budget.
No group grant, epoch publication or delivery is enabled here.


Authenticated media owners can call `POST /acl/sociacl/media/owner/group-view`
with only `object`, and `group-append` with `object`, `at`, `fence`, `predicate`,
`set` and signed `rows`. Both retain the existing fixed subject/tenant binding,
`acl:media:write` scope, rate limits, body/concurrency limits and private no-store
responses. Unsupported older authority adapters refuse with 503. A group append
still verifies every retained signature and preserves cancellations; these routes
do not issue group grants, epochs or reader wraps, or enable group delivery.

The native group settlement-policy adapter verifies an existing signed
`GroupEpochConfig` against independently resolved owner/key/scope/window/revision
fields. It does not select the current policy, establish set ownership or grant
media delivery. Protected group policy persistence and source consumption remain
separate from this bounded adapter; existing direct-media routes are unchanged.

### Protected group policy source

The source's `group_policy_view` and `append_group_policy` methods retain at most
64 set-owner-signed settlement configurations per media object. They require the
media owner's authenticated writer, a current write fence and an already admitted
group scope. Set ownership and its current signing key are resolved separately
from the media owner through the protected enrolled histories. The installed
SociACL native verifier authenticates the exact scope, revision and window.

Reads revalidate every matching configuration under the current set-owner key,
then select the greatest revision, breaking ties by the smallest canonical signed
transcript digest, as in SociACL. A key change that leaves no current signature
returns no policy. Exact retries do not change the source; new rows advance its
checkpoint and object version. Capacity never prunes signed history. These methods
do not turn group members into direct grants, select media epochs or deliver wraps. Existing direct-media behavior remains unchanged.

`POST /api/v1/acl/sociacl/media/owner/group-policy-view` accepts exactly
`{object, predicate, set}` and returns `{at, context, config, fence}`. The context
contains the currently resolved set owner and signing key; config is the selected
signed policy or null. `group-policy-append` accepts exactly
`{object, at, fence, predicate, set, config}` and returns `{accepted: true}` only
after protected admission. Both use the fixed authenticated writer binding and
`acl:media:write`, private/no-store responses and existing bounded worker slots.
The view is capped at 2 KiB and append at 18 KiB; duplicate JSON fields refuse.
Stale writes return 409 without automatic retry. Older sources without these
methods return 503; direct owner routes keep their existing contracts.

`POST /api/v1/acl/sociacl/media/owner/group-authority-view` takes only
`{object}`. The fixed authenticated media owner receives `at`, `fence`,
`objectVersion`, `owner`, the direct `direct` snapshot, the independently admitted
all-scope group `projection`, selected signed `policy` (current set-owner context
and nullable config), and current `bindings` limited to the named parties.
All inputs share one protected database transaction and current identity history.
Missing named bindings refuse. A missing or no-longer-valid signed policy is null,
so consumers cannot treat a pending policy as authorization. Direct entries and
group membership remain separate; this preparation view creates no epoch, wrap,
or delivery grant. Group row changes advance the object version; exact retries
do not. Existing direct and group-view routes retain their response shapes.

`POST /api/v1/acl/sociacl/media/owner/group-check` accepts
`{object, predicate, set, rows}` for an exact bounded signed batch. It returns
`{at, state, fence}` under current protected authority. `applied` means every
exact row is retained; otherwise `absent` means the batch is not fully retained.
Partial overlap is allowed because a batch may repeat existing object rows.
Both results reverify the combined rows against current enrolled histories.
The read creates no rows or versions. An applied older row does not revive a
cancelled edge or grant access. After an absent result, explicit append must use
the returned fence; an intervening authority change still refuses the write.

`POST /api/v1/acl/sociacl/media/group-consent-view` accepts exactly
`{object,predicate,set}` under the existing `acl:media:read` binding. The member
comes from the authenticated subject's configured reader, never request JSON.
The protected source reads retained rows, current enrolled histories and the
source fence together. A current set-owner assent naming that member is
required; withdrawals or unacknowledged cancellations refuse preparation.
The response contains separate admitted consent state and a member-only unsigned
`draft` with the next safe HAM state, server `issuedAt`, and cancellation IDs.
The caller must choose `stated` before signing. No member write, epoch, direct
grant, wrap or delivery is performed by this route. Member append capacity and
group-wide epoch delivery remain separate unfinished work.

New group journal writes reserve one canonical `stated: 0` row for each party's
active assent and each active object-set edge, within both the per-scope row
limit and aggregate byte limit. Equal-HAM withdrawal wins under native ordering,
including at the maximum safe HAM value. A withdrawal may use an empty cancel
list because stated 0 removes assent independently of cancellation observation.
The protected document also reserves the remaining bounded group envelope so
ordinary direct-media writes cannot consume that space. Existing journals keep
their prior direct-unshare budget until a group write can adopt this rule
atomically. These are capacity guarantees, not membership or delivery authority;
current histories and signatures still must pass admission.

Reservation-enabled journals also preserve maximum-width `objectVersion` bytes
and remaining version increments for active group and direct removals. Ordinary
writes cannot use the last increment needed for those withdrawals.

A fixed reader binding with both `acl:media:read` and `acl:media:write` may submit
its own signed member row to `/api/v1/acl/sociacl/media/group-consent-append` with
`{object,predicate,set,row,at,fence}`. The source admits the exact signed row,
requires its member/role to match the authenticated binding, and compares a new
row with the current protected preparation draft before appending atomically.
An owner/set-role row cannot be submitted through this endpoint.

`group-consent-check` takes `{object,predicate,set,row}` and reports exact
`applied` or `absent` state without writing. Reconcile after a lost response;
do not create a replacement signature blindly. An already retained row stays
applied even after subsequent withdrawal, without restoring membership.
`group-withdrawal-view` takes `{object,predicate,set}` and prepares the member's
own current assent removal even when the invitation was withdrawn. It uses a
same-HAM stated-0 response with empty cancellations, within the reserved capacity.
All three routes retain the fixed reader binding and bounded worker/transport
limits. Member writes do not create direct grants, epochs, wraps, or delivery.

A newly applied member signature may be at most four seconds old at the fresh
source fence. Its original `issuedAt` is preserved across second boundaries;
all other draft fields must still match current preparation. Exact applied-row
reconciliation remains available after that signing window expires.

Member consent writes retain at most eight positive member assents per object
across all group scopes for each enrolled member. Exact retries consume no
capacity. Withdrawal remains available through its reserved capacity after the
limit; changing scope or signing again does not reset the retained history.

The native `groupCohortGraph` preparation mode accepts only membership and
membership-cancellation rows for one predicate and set. It rechecks current
identity histories, returns separate current public bindings for the set owner
and named members, and projects membership ordering without any media edge.
It does not create a group store, grant access, select an epoch, or deliver a
key. Media-object and object-set rows are refused in this group-wide mode.

Protected group storage is prepared separately from per-object media documents.
`install_group_media_journal` explicitly adds an empty group document table and
an independent checkpoint table to an already-provisioned PostgreSQL source.
It refuses partial or repeated installation; runtime construction performs no
DDL or repair. Existing media processes and source-marker versions remain
compatible. No endpoint or environment switch enables group delivery here.

`GroupMediaJournal` reads and writes within the caller's source transaction.
The caller must admit current histories, group signatures and authorization in
that same transaction. Exact-document compare-and-swap, independent scoped
checkpoints, random nonces, bounded revisions and a 64-group/4-MiB-document
limit protect retained state. This storage primitive neither accepts keys nor
decides membership, epochs or access. Restored or missing state with a surviving
checkpoint is refused; it cannot protect against a coordinated rollback of both
independent stores. Group key wrapping and delivery remain separate work.

The internal `GroupSource` creation command uses an already owned, active media
object only as the trusted policy anchor. It resolves the set owner's current
history, binds the preparation fence to the group scope, and requires the
current set-owner signature on the group configuration. Creation copies the
protected policy into an independent, empty group document. No member is added
implicitly and no epoch, key or media grant is created. Existing groups cannot
be overwritten. These commands are not exposed through HTTP or activated by
this change; later membership and delivery work must consume this independent
group state rather than silently importing per-object preparation rows.

`groupMemberStateGraph` resolves one member's admitted assent state and the
current signing keys of both parties without requiring a media-object edge or
an encryption key. It is preparation for membership changes, including removal
after a signing-only rotation. It cannot authorize encryption-key delivery;
`groupCohortGraph` retains that stricter current-encryption-key prerequisite.

The internal `GroupMembership` commands prepare and append a set owner's
invitation or a member's own response in the independent group journal. Current
signing histories authorize each party separately; joining requires a current
invitation and acknowledges retained cancellations. Either party can remove its
own assent at the same HAM value without an invitation or encryption key.
Exact retained rows reconcile after lost responses. New rows must match the
protected draft, source fence and four-second signing window. Positive history
is bounded per party/member, with reserved row, byte and revision capacity for
withdrawals. Membership writes do not create media grants, epochs or key wraps.

`/api/v1/acl/sociacl/media/groups/{action}` exposes bounded creation and
membership commands through existing fixed private-media identity bindings.
Both media read and write scopes are required; the authenticated binding
supplies the writer, never request JSON. Actions are `create-view`, `create`,
`create-state`, `member-view`, `member-append` and `member-state`. Bodies contain
only the action's group scope and draft/command fields. The handlers share
existing request, tenant and source worker limits and return private/no-store
responses. They perform no installation: missing PostgreSQL group tables refuse
operation, and existing SQLite-backed media flows remain unchanged. No group
key delivery or media authorization is enabled by these routes.

`POST /api/v1/acl/sociacl/media/groups/catalog` takes only `{page}` (0–15)
under the existing fixed reader binding and media read/write scopes. Each page
examines at most four independent group documents and verifies their checkpoints,
current identity history and membership policy in one source transaction. It
returns only groups owned by this principal, active memberships, or current
set-owner invitations acknowledging all retained cancellations. Each result has
`predicate`, `set`, `owner`, `owned`, `invited`, and `active`; the response also
contains `at`, the fixed `principal`, and `nextPage`. The sixteen-page envelope
is fixed even for empty pages. Candidates can shift between requests, so clients
refresh and deduplicate rather than treating pagination as a stable snapshot.
No keys, wraps, storage locations or unrelated group details are returned.
An accepted membership or a catalog entry does not authorize media delivery.

`GroupKeySource` prepares and retains independent owner-signed group key epochs.
It builds each snapshot from the protected current cohort and current signing,
encryption and identity-head bindings, with no implicit owner membership. The
current owner-signed group policy must still verify. A fresh group-specific
fence binds the source document and identity authority to the server evaluation.
Each append is the exact next epoch and finalization in the protected chain;
server first-seen time is retained and exact retries never restart settlement.
The journal preserves room for membership withdrawals. Exact-command state reads
support lost-response recovery without producing replacement signatures.
These internal methods do not grant media access or publish keys. HTTP wiring,
recipient-wrap storage and delivery checks are separate consumers.

The fixed-principal group command routes also provide `key-view`, `key-append`
and `key-state`. Preparation takes `{predicate,set}`; append adds the fresh
`at`, `fence` and exact signed `command`; recovery takes `{predicate,set,command}`.
A command contains `{document:{manifest,snapshot},finalization}`. Only the
currently authenticated group owner can use these operations. The outer key
append/state body is capped at 72 KiB and the signed command at 64 KiB. Other
group actions retain their existing 18 KiB transport bound. Existing worker,
rate, cancellation and tenant capacity controls apply. No route accepts a caller
chosen writer or supplies a group key, reader wrap or media authorization.

## Independent group allocation

`SOCIACL_GROUP_ALLOCATION_FILE` separately enables
`POST /api/v1/acl/sociacl/media/groups/allocate` for configured tenant/subject
bindings with `acl:media:write`. The body contains only `predicate` and `set`.
Current native owner checks, configured source signing and issuer verification
precede atomic group allocation consumption. The browser cannot choose owner,
policy, issuer, keys or storage authority.

The private binding file uses only the PostgreSQL version-2 allocation format,
with `postgresFile`, fixed subject/reader, Storage origin/key file, issuer/source,
policy file/expiry, source key file and issuer public keys. Both group history
and group allocation journals must already be installed. Loading checks their
presence but never creates tables or grants. The group Storage credential must
have `storage:group-allocations:issue`; media allocation scope alone does not
work. Missing configuration disables the route. No deployment is activated by
adding these modules.

The protected group key source can issue a two-second read permit only for an
explicit current member of an allocated group whose latest key has settled.
The permit binds the current recipient encryption key, epoch, revision, key
commitment, group document and complete authority checkpoint. Final delivery
must revalidate it in the protected write transaction. Owner status is not
implicit membership, and old epochs are never a fallback. This internal source
boundary does not expose bytes or activate a delivery route.


Protected group wrap publication reserves one immutable digest and length for
an epoch/recipient before provider upload. Failed uploads retain their reservation;
retry uses the same encrypted bytes. Publication commits only after rechecking
current owner, member encryption binding and native group history. Reads select
only the latest settled epoch's published wrap and revalidate the complete permit
before returning bytes. Source document/revision capacity preserves room for
withdrawals. This source module activates no public transport or credentials.


The group wrap coordinator connects protected source reservations and final
commits to a group-bound Spanopticon client. The client uses only canonical set
identifiers and exact digests, verifies returned bytes, and never redirects or
retries writes automatically. Delivery returns the selected key commitment and
recipient context after the protected source commits, omitting internal fences.
All source operations run through the existing bounded worker boundary. Runtime
configuration and browser/public routes remain separate activation work.

The protected group wrap view returns the current owner-only manifest and cohort
with a fresh write fence. It remains available at the 64-epoch history limit,
since publishing a recipient wrap does not create another epoch. Both the view
and publication require the latest manifest snapshot to match the current cohort
and enrolled identity keys. Changed membership or identity keys require a new
valid epoch before publication can proceed.

`SOCIACL_GROUP_WRAP_FILE` explicitly enables group wrap delivery. Its private JSON
uses media-binding version 2 with `tenant`, `subject`, `reader`, `postgresFile`,
`storageOrigin` and `storageKeyFile` per binding. The protected group journals must
already exist. When group allocation is configured, wrap delivery shares its
exact protected source and storage origin. The separate storage credential needs
`storage:groups:wraps:read` and `storage:groups:wraps:write`; browsers never receive
it. Missing configuration disables these routes; loading does not install schemas.

Authenticated POST routes under `/api/v1/acl/sociacl/media/groups` are `wrap-view`,
`wrap-publish` and `wrap-read`. All take `predicate` and canonical `set` identifiers.
Publication also takes `at`, `fence`, recipient `metadata` and canonical base64
`payload` (at most 64 KiB decoded). View and publication require `acl:media:write`;
read requires `acl:media:read`. The reader/owner always comes from the configured
subject. Read returns base64 ciphertext with the current epoch, revision,
recipient encryption key and group key commitment. Responses are private and
uncached. Authority changes return 409; callers must reconcile before retrying.

The internal group item preparation reads the media owner's current authorized
item context and that same owner's settled group key context in one protected
source transaction. Its short-lived fence binds both selectors and their
checkpoints. It returns no key or storage location and does not create a media
grant, object-set binding, publication or delivery permission. Group item-key
publication and read authorization remain separate consumers of this context.


The internal `deliver_group_item_wrap` coordinator accepts only a joint immutable
item/group permit from a configured authority. It reads opaque bytes through the
media object's allocation, verifies length and digest, and requires a second
protected commit before returning. Item and group epochs remain separate in the
returned context. The authority contract requires current item grant/status,
settled epoch, group membership and both protected checkpoints; group-key access
alone never qualifies. The protected media source supplies the joint authority methods. No HTTP route
installs this coordinator. Status and wrap publication remain separate consumers.


Group item grants use their own bounded `groupItemGrants` journal; they never
enter the direct `grants` list or authorize a direct wrap. The owner prepares a
signed grant through `POST /api/v1/acl/sociacl/media/groups/item-grant-view`
with `{object, predicate, set, reader, withdraw}`. Positive drafts require the
current signed item-to-group binding, explicit current owner and recipient
membership, and the owner's current item access. They bind the next item epoch,
current ciphertext digest and validity bounded by both policies; insufficient
remaining time for the signed group settlement window refuses preparation.
Cancellation drafts preserve the retained scope and dates and remain available
after the owner or recipient leaves the group.

`item-grant-append` takes `{object, predicate, set, at, fence, payload}`, where
payload is the native signed `{claims, proof}` (at most 4 KiB). Both endpoints
require the existing fixed subject binding and `acl:media:write`. Current owner
signatures and exact source drafts/fences are mandatory for new grants. Same
claims at an already retained revision are idempotent; a signed same-revision
fork permanently freezes that scoped recipient and preserves the conflicting
record. The journal reserves cancellation/fork space and object versions across
ordinary media writes. These grants still require current group-aware epoch,
status and wrap admission before delivery; neither endpoint publishes bytes.

`item-grant-state` accepts `{object, predicate, set, payload}` and reports
`{at, state, frozen}` for interruption recovery. Exact retained proofs remain
queryable after the write window or owner key rotation; alternative proofs must
verify against the current owner key. An applied result confirms retention only,
including cancelled or frozen history. It neither refreshes a signature nor
creates a delivery grant. Saved absent commands must retain their original
write time and fence; an expired command is not silently re-signed.

### Contact descriptors and encrypted private state

`SOCIACL_CONTACT_BINDINGS_FILE` enables `/api/v1/acl/sociacl/contacts/read` and
`/write` for explicit tenant/subject bindings. Version 1 configuration has
`bindings` rows containing `tenant`, `subject`, `principal`, `postgresFile` and
`policyFile`. All configuration files are private regular files. `postgresFile`
uses the existing PostgreSQL source format. `policyFile` contains version 1,
integer `from`/`until` seconds and `trust` with `jwks`, `policy` and `pinnedIss`.
Expired trust refuses both reads and writes. Missing configuration disables the
routes; runtime construction does not install tables or enroll identities.

The contacts installer in `infrastructure.contact_journal` creates two absent
relations in already provisioned source/checkpoint schemas. It is an explicit
operator operation, not a startup step. Public descriptor bytes and encrypted
vault bytes have separate revision counters and checkpoints. A signed disabled
advertisement retains its descriptor revision. Private vault reads require the
bound owner; descriptor reads require an authenticated enrolled reader. The
vault is at most 1 MiB and may contain only client ciphertext; no unlocked
keyring is sent to this service. The caller retains encrypted contact decisions,
blocks and retry state within that vault.

Both requests contain `owner`, `kind` (`descriptor` or `vault`) and `evaluatedAt`.
Writes also contain `revision` (the expected committed revision, initially zero),
canonical base64 `payload`, the read response’s `fence`, and a current-owner `signature`. The signature covers
SociACL length-prefixed strings: `s3rch-contact-document-v1`, tenant UUID, source
UUID, owner principal, kind, expected revision, evaluation second, read fence, and lowercase
SHA-256 of the decoded payload. Descriptor payloads are UTF-8 JSON with exactly
`advertisement`: a verified signed first-contact descriptor whose revision equals
the next storage revision, or `null` to disable discovery. Reads return revision,
base64 payload (or null), an authority fence, and the current verified owner key head.
The fence covers complete source identity history and configured trust policy;
changes to either refuse an otherwise current document revision. Mutations
return the committed revision and payload digest. Conflicts require a fresh read
and signature; an ambiguous response must be reconciled against retained bytes.

Admission verifies complete enrolled identity history and the source checkpoint
while holding the same transaction lock as the document update. Separate
checkpoints reject missing or restored document rows. These contracts do not yet
provide contact-secret recovery, grant delivery or message admission.

`/contacts/config` accepts only `evaluatedAt` and returns the authenticated
binding's principal, current key, tenant/source identifiers and configured public
trust policy. Document reads also return the source's complete public identity
history for browser verification; they do not install a new witness policy.
Clients bind that history to the independently fetched configured trust and never
substitute a returned key head for history verification. The explicit installer
accepts `active_media_index=True` for already-upgraded version-2 source markers.

`POST /api/v1/acl/sociacl/media/groups/item-epoch-view` prepares the next complete
item snapshot for the authenticated owner and selected live group binding. It
returns owner-signing context, the current direct recipients' next-epoch grant
drafts, the native object-set/membership projection joined with separately signed
group item grants, the current group settlement window and a joint fence. A live
direct grant takes precedence when the same accessor has both scopes; otherwise
a live group grant can supply that accessor's row. The two source journals remain
independent. Expired direct recipients receive cancellation drafts, and unsigned
membership alone never adds a private recipient. Missing authority, changed keys,
insufficient validity or capacity refuse. This route is read-only; epoch admission,
status and item-wrap delivery must still complete before group access is usable.


The internal `GroupItemSource.append_epoch` atomically checks the exact prepared
recipient drafts, owner-signed private grants, native manifest and finalization,
unchanged item-key commitment and ancestry before retaining the next item epoch.
It records the command digest in the same checkpointed media write. Exact retry
and `epoch_state` confirm retained bytes without re-signing or implying current
access. Authenticated owner HTTP append/state routes expose this admission.
Native and transaction contracts run only in CI.

The read-only [SEA device-transfer authority](docs/device-transfer.md) supplies
scope-bound current identity/history decisions for the shared browser SDK.
Its browser adapter uses the supported `sociacl-ids/keyring` surface. Explicit
subject bindings and expiring transfer eligibility are required; no private SEA
keys or uploaded history are accepted by the authority service.

The internal group-item read authority joins a current owner-signed item grant,
independent current membership and group-key permit, native settled item history,
current owner-signed status and exact item/group wrap metadata. It rechecks the
same authority after the coordinator fetches bytes, before observing floors or
releasing data. A live direct grant retains precedence over a group grant for the
same reader. Missing status or publication metadata refuses by default. This
adds no public read route or epoch-write route; combined direct delivery and the
owner status/publication path must be completed before installing those routes.


The internal group-item status preparation uses the same current grant,
independent group membership/key and native settled item selection as delivery.
Only the authenticated media owner receives the signing draft. Admission binds
its current joint fence, exact signing time and lifetime, owner signature and
object-version snapshot; it keeps at most 64 statuses without advancing the
object version. It does not require a previously published wrap, avoiding a
status/publication dependency cycle. Authenticated owner HTTP routes expose
status preparation, admission and exact retained-command reconciliation.

Exact status retries confirm checkpointed identical bytes before comparing the
old preparation fence. `group_item_status_state` reconciles retained bytes after
the signing window or current access has changed; an applied result never means
that the status is still fresh or grants current access.


Internal group-item wrap publication reserves one exact opaque payload per
item/group epoch pair, with at most 64 reservations. The owner supplies a current
group-granted reader as the authorization anchor; its private grant, independent
membership and settled item/group history must remain current. The coordinator
writes only through the media object's storage allocation and commits the
protected metadata after storage confirms its digest. Commit rechecks both
checkpoints and expiry. Publication advances the object version, so signed
statuses must be refreshed afterward. An uncertain upload can reconcile the
same bytes using a fresh preparation view; replacement bytes for the same epoch
pair refuse. No publication or delivery HTTP route is installed by this change.


Direct delivery for an item with combined group epochs selects against the same
current complete grant/membership snapshot and group settlement window. It still
requires its own current direct grant, owner-signed status, identity and direct
wrap; group access never substitutes for those checks. The direct permit also
binds the independent group checkpoint through its final commit. Historical
parent selection uses the exact epoch's recorded group window, and selection
cannot fall back below the latest combined epoch. Group journal construction can
reuse the caller's already-owned PostgreSQL transaction after verifying its store
and schema scope; it does not open a nested transaction. Owner repair and public
group delivery installation remain separate work.


Group epoch maintenance prepares metadata independently of read authorization.
It requires the current tenant-bound owner, a live nonfrozen owner-signed direct
grant, the item digest already bound in the protected owner wrap, and an
authentic settled historical parent at the protected floor. Preparation and
append bind the same key commitment and current joint authority. A missing or
stale read status therefore does not prevent the owner from preparing a repair;
no wrap bytes, read permit or keys are returned. Positive group changes still
require the owner's explicit current group membership. A separate negative-only
detach path is still required when the owner has left the group.


After the owner signs an object-set withdrawal, metadata-only maintenance can
prepare a detached item epoch without loading independent group membership.
Every group-derived row is inactive; independently signed direct grants are
refreshed under the authentic historical parent's settlement window. Publication
and fresh status still precede direct delivery, and group delivery remains
refused. The same negative snapshot is used by direct selection after admission;
there is no fallback to a prior positive group snapshot or an earlier epoch.


The application installs `owner_router` under `/api/v1/acl/sociacl/media/groups`
for `item-epoch-append`, `item-epoch-state`, `item-status-view`,
`item-status-append`, `item-status-state` and `item-wrap-view`. These six owner
commands require configured tenant/subject bindings and `acl:media:write` scope.
Missing runtime bindings remain unavailable. The wrap view returns metadata,
not encrypted bytes or keys. CI checks application installation, fixed-subject
owner binding, strict bounded JSON, private responses, capacity and cancellation.
Epoch bodies are capped at 270336 bytes and signed status commands at 8192 bytes.

The application installs `item_byte_router` for `item-wrap-publish` and
`item-wrap-read` under `/api/v1/acl/sociacl/media/groups`. Its commands use the configured
private media binding and shared private-media capacity limits, never the group
key store. Publication is owner-bound and read delivery is fixed to the
credential's reader. Current joint authorization and item allocation checks
remain in the domain/source coordinators. CI exercises both paths through the
assembled application. Missing private-media runtime bindings refuse requests.

### Group owner wrap maintenance

`GroupOwnerWrapSource` prepares and rechecks a separate owner-only permit for the
existing encrypted owner wrap of an authentic settled maintenance parent. The
current signed owner grant, enrolled encryption key, item digest, matching wrap
revision, current attached or detached item scope and protected checkpoints are
mandatory. The permit is valid for at most two seconds. It does not authorize a
recipient read or advance an item epoch. The authenticated owner route uses the
private-media allocation and rechecks this permit after storage returns.

This supports preparing replacement direct-recipient wraps before an atomic group
item epoch update. A browser must retain those opaque wraps before submitting that
update and reconcile their publication afterward; command acceptance alone does
not complete key delivery.

The installed `owner_wrap_router` exposes `item-owner-wrap-read`. It requires the subject-bound private-media binding and `acl:media:write`,
accepts only object and group scope, and reads through the item allocation. The
coordinator verifies the returned bytes and rechecks the owner permit after storage.
Normal reader routes are unchanged.
