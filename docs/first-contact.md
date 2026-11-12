# Public first-contact ciphertext transport

This implements the storage boundary for FyberLabs/SociACL#70. Through the
configured Spanopticon HTTPS origin, GET and POST use
`/api/v1/acl/sociacl/first-contact/{64-lowercase-hex-channel}/messages`.
POST is raw `application/octet-stream`; GET returns the existing bounded
`messages: [{id, ciphertext}]` representation with canonical base64 ciphertext.
IDs are SHA-256 of ciphertext. A matching digest is not sender authentication.

The public queue has a separate table, advisory lock and global budget from
accepted private contact lanes. Limits are 94..8192 bytes per message, 128 rows
and 1 MiB per channel, 10 new writes per minute per channel, 4096 rows and 32 MiB
globally, with seven-day expiry. Exact retries neither consume quota nor extend
expiry. The edge applies the anonymous client-address rate bucket, strips identity
headers/cookies, rejects redirects at the client, caps request bodies at 8192
bytes, and gives public requests eight separate in-flight slots. Queue exhaustion
returns 429; missing schema/storage returns 503. New routes do not exempt other
SociACL identity or recovery endpoints from authentication.

The database owner supplies additive migration `platform_0087_first_contact`.
Services keep their moving TEST channel; there is no matching-build requirement.
The previous private-lane contract remains compatible. Deploying a service before
the additive schema is available fails closed for the new route.

Clients must authenticate fresh opt-in descriptors, encrypt before transport,
verify sender history after opening, reserve replay protection, and require
explicit recipient acceptance before creating a private-lane grant. The service
never decrypts, discovers identities, accepts a contact, or grants access. Disabled
or rotated channels may still receive bounded garbage until expiry; recipient
admission must reject them. Authenticated descriptor publication/discovery and
product UI remain separate work. No principal, tenant, signature or secret name
is stored beside ciphertext, and access logs redact channel IDs and query strings.

PR CI exercises mocked route/client contracts and quota boundaries. Database
concurrency, retry, isolation and expiry checks belong only in scheduled CI.
