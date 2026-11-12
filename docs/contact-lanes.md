# Contact-lane ciphertext transport

Spanopticon is s3r.ch's external service interface. Its controlplane-edge forwards
`/api/v1/acl` to acl-service. The ACL service owns these lane operations; the
platform migration `platform_0086_contact_lanes` owns the PostgreSQL table.
Apply that additive migration through the normal database delivery before using
this API. Missing schema or storage returns 503; the API never substitutes memory.

- `POST /api/v1/acl/sociacl/contact-lanes/{laneId}/messages`: raw
  `application/octet-stream` ciphertext, 32–65536 bytes. Returns its SHA-256 `id`.
- `GET` on the same path: `{messages: [{id, ciphertext}]}`, with standard base64
  ciphertext. At most 128 messages / 1 MiB of raw ciphertext per lane.

Lane IDs are the canonical 64 lowercase hex ObjectId returned by SociACL's lane
lookup helper. Never use a PrincipalId, `~pub`, sender, recipient or tenant path.
Possession permits transport only. Storage cannot prove bytes are encrypted or
sender-authentic: callers must seal signed envelopes before POST and decrypt,
verify sender signatures and current grants before consuming GET results.
No endpoint creates a grant, derives a lane, or accepts a stranger contact.
No lane enumeration, account index, overwrite or deletion API is exposed.

The edge permits only exact GET/POST paths without a session JWT and keeps its
anonymous client-address limiter active. Clients send no cookies, tenant header
or account credential on these paths. Keep the ACL service private behind the
edge. Redact opaque lane paths from access logs and do not link them to accounts;
timing, sizes and network addresses remain visible to infrastructure operators.

PostgreSQL serializes appends across service instances. Limits are 30 new
messages per lane per rolling minute, 128 messages and 1 MiB per lane, and 4096
messages / 64 MiB for the store. Limits return 429. Identical retries are
idempotent and do not refresh expiry. Retention is seven days from the server's
insertion time. Reads omit expired rows; subsequent writes prune them. These
are bounded transport defaults, not authorization or delivery guarantees.
Database access is restricted to the ACL service role and migration owner.

PR CI covers route and quota contracts with mocked storage. The nightly
PostgreSQL suite covers concurrent quota admission, retry and expiry. No caller
may interpret storage success as sender authentication or permission to read an
underlying SociACL object.
