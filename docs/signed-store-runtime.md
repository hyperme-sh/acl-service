# Protected recovery and wrap storage bindings

`SOCIACL_SIGNED_STORE_BINDINGS_FILE` is absent by default. It names a private,
absolute regular JSON file with `version:1` and up to64 `bindings`. Each binding
has `tenant`, `subject`, `principal`, `postgresFile`, and `policyFile`. The
existing authenticated subject and tenant select one enrolled principal; request
bodies cannot select another owner or a storage source.

`postgresFile` uses the existing protected PostgreSQL source settings. The source,
independent checkpoint schemas, least-privilege role and enrolled history must
already exist. Loading creates no schema, account, grant, floor or checkpoint.
`policyFile` has exactly `version`, `from`, `until`, `trust`, and
`activePrincipals`. Times use whole Unix seconds. Trust has `jwks`, `policy`, and
`pinnedIss`. The policy is reloaded for every operation and checked again through
the final ciphertext commit guard. Removing a principal or changing policy
refuses in-flight delivery or writes. Existing native verification enforces the
current signing key, complete history, fork refusal, shared floor and generation.

The existing `/acl/sociacl/keyring/{kind}/operations` and
`/acl/sociacl/keyring/{kind}/rows/{target}` contracts are unchanged. A conflict
requires rereading all signing inputs. Lost responses require exact authenticated
read-back before considering another signed write. This source connection alone
does not implement browser rotation or server-persistence presentation.

This change adds no reader registration or live configuration. Dedicated
PostgreSQL authenticated-API, role and restart acceptance remains tracked by
#13/#14; the policy and configuration units supplement existing native-store
contracts without claiming those remaining acceptance items complete.
