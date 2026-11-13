# Trusted signed statement source

`admission.statement_source.StatementSource` implements the source required by
s3r.ch #279/#389. It colocates graph rows and policy with ACL's exclusively
admitted identity history in one tenant's SQLite database. This is a single-host
owner adapter, not a replica-local cache. Every identity writer must use the
same HistoryStore. Imported peer histories cannot establish completeness.

An operator provisions a new empty graph with a fixed forum, independently
trusted witness policy, policy expiry and an explicit exclusive-from-creation
graph grant. Provisioning rechecks that grant at commit. It neither enrolls an
identity nor imports ACL rows. Signed initial forum ownership and direct see/post
grants are admitted using `append(..., statement_only=False)` by trusted operator
code. There is no public bootstrap, policy-update or identity-enrollment route.
The initial graph supports signed object, direct see and direct post records,
including signed cancellations (`stated: 0`). Group rules are refused rather
than treated as implicit membership. The original signed rows are retained.

Each read resolves all enrolled chains using the pinned SociACL verifier and
service-selected policy. Valid forks, expired policy and incomplete history
refuse the operation. The response is the s3r.ch `ForumAuthoritySnapshot` plus
an opaque fence. The fence binds tenant, graph, evaluation second, policy/graph
revision and complete identity authority digest, including monotonic floors.
A write checks it under the same SQLite write lock, verifies the new signatures
and current direct forum access, and checks the evaluation second immediately
before commit. Identity, cancellation, policy or graph changes invalidate it.

The two additional tables in the authority database contain tenant binding and
graph documents. Protected deployments keep each graph's revision/content digest
in `statement_checkpoints` in the independent freshness database, updated in the
same attached transaction. Ledger-only graph rollback is rejected. Restoring both
stores together remains outside the independent-checkpoint guarantee. Missing
checkpoints are not automatically repaired from the ledger.

## Authenticated transport

The app factory accepts an immutable mapping of `(tenant UUID, authenticated
service subject, scope)` to `StatementBinding`. This is a private service binding;
browser identities do not select an arbitrary graph or source. Runtime transport
requires a source using independent authority checkpoints and the real verifier.
No binding means 503; an unrelated subject or tenant gets 403.

POST `/api/v1/acl/sociacl/statements/{scope}/snapshot` takes only
`{"evaluatedAt": <integer>}`. POST `.../append` takes `evaluatedAt`, `fence` and
`rows`. Append returns `{"ok": true}`. A changed fence/deadline is 409 and requires
a fresh read and authorization; writes are never automatically retried.
Responses are private and noncacheable. Both requests require the existing
verified bearer and matching `X-Tenant-ID`.

HTTP input is bounded to 70,000 bytes and two concurrent backend operations.
Timeouts retain capacity until the backend thread stops. Each source append is
at most 65 rows/64 KiB; retained rows are bounded to 1,024 and snapshots to 4 MiB.
The source checks the deadline at commit even when the HTTP caller times out.
A lost response can be ambiguous: reread before resubmitting signed rows.

`replace_policy` is operator-only, checks explicit authorization at commit and
increments the graph revision. Deployment supplies authenticated policy and
exclusive graph enrollment; request JSON cannot supply either. The API does not
mint grants, sessions, private keys or a claim that an arbitrary Gun view is
complete. Gun may carry the same signed records as a transport.

Unit transaction cases use a stub verifier. Cryptographic owner/consumer and HTTP
contracts run in CI. This adds the source contract; s3r.ch consumer activation
and removal of the legacy assignment journal require their own changes.
