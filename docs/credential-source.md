# Complete credential authority source

ACL #189; consumers Auth #69 and s3r.ch #444/#583.

`POST /api/v1/acl/sociacl/credential-source/read` is unavailable without
`SOCIACL_CREDENTIAL_BINDINGS_FILE`. It requires a matched authenticated tenant,
the exact configured service subject and `acl:identity:credential-source` scope.
Do not grant this scope to browser users: the response contains private identity
history for the configured domain. No new policy, schema or fixture is installed.
Readers remain unregistered.

The private bindings file is `{ "version": 1, "bindings": [...] }`. Each row has
exactly `tenant`, `subject`, `postgresFile`, `policyFile`. The PostgreSQL file uses
the existing protected history/checkpoint source format. The policy file has
`version: 1`, integer second `from`/`until`, and `trust` containing `jwks`, `policy`,
`pinnedIss`. Files use the existing absolute private-file checks. Policy is read
for each request and compared again before commit; changing or expiring it refuses
the request. No caller can select a principal or restrict the source domain.

Request: `{ "credential": ..., "evaluatedAt": <current Unix second> }`.
A wallet credential has exactly `kind: "wallet"`, `address` (EIP-55).
An OIDC credential has exactly `kind: "oidc"`, `iss`, `tenant`, `sub`.
This endpoint does not authenticate a wallet or provider proof and cannot issue a
session. Auth/the existing SEA issuer must bind and verify fresh proof separately.

Version 1 response has `version`, `tenant`, `source`, `authorityDigest`, `trust`,
and `snapshot`. The snapshot contains `completeThrough`, the exact `credential`,
matching `links`, all `revocations`, and `history` with `completeThrough`, all
`links` and all `accounts` (`principal`, `rotations`, `revocations`,
`genesisEpubBindings`). The digest identifies the protected source state; it is
not a public signature or a reusable login authorization. Consumers must verify
their configured tenant/source and trust policy, reconstruct the authenticated
history callback with shared SociACL helpers, and re-resolve immediately before
issuance. They must not cache this response as permission to issue later.

Completeness is explicitly limited to the entire configured authority source,
whose identities must have been enrolled under exclusive admission from genesis.
It does not claim knowledge of arbitrary external links. All enrolled histories
are read under the same PostgreSQL source lock and independent checkpoint used
by admission. No secondary credential index or caller-filtered completeness flag
exists. Accepted current rotation floors advance in that transaction. A restored
history inconsistent with its independent checkpoint refuses. An interrupted
transaction cannot publish a partial result.

The response refuses frozen/future/invalid histories, two independently eligible
principals even with different link timestamps, changed policy, clock changes,
cancellation, and excessive input/output. Revoked links remain represented so
consumers can independently establish their ineligibility. Bounds are 64 accounts,
128 matching links, 1024 revocations, 4096 total links and 4 MiB; exceeding a bound
refuses the whole lookup instead of claiming a truncated page is complete.

Pure adapter units substitute storage and the native boundary. Native signed-link,
HTTP, and PostgreSQL contracts run in CI only. Deployment/configuration and browser
acceptance are separate from implementing this source contract.
