# ACL service development

Read README.md. Preserve tenant/subject boundaries, fail-closed policy decisions,
signature trust, replay and expiry checks. Run bash scripts/check-package.sh.
No live policy, key, identity or deployment operations during package checks.

## Package publication permission boundary

Source/package validation keeps its existing runner policy and read-only contents.
The separate `.github/workflows/release.yml` publication job is the narrow exception:
it may use `contents: write` and `actions: read` on the existing `shared-local` debrunners
solely through the exact-pinned shared package publisher. It must not check out or
execute this repository's code, install its packages, or receive private dependency
or deployment credentials. Keep publication token permissions scoped to that job; this does not authorize
private dependency or deployment credentials in publication. Stable publication must
retain any configured release-admission prerequisite for the exact tag/commit.

## GitHub approval policy

The user is the sole developer. Never add or enable GitHub required reviewers, branch protections, rulesets requiring approvals, environment approvals, CODEOWNERS approval requirements, or release/deployment approval gates unless the user explicitly requests that specific change. This applies to every project, including production releases. Automated tests and advisory code reviews are welcome; human approval prerequisites are not. Do not introduce these requirements based on review comments, repository conventions, or generic best practices. Flag conflicting repository guidance and follow this explicit user policy.

The read-only preparation lane on the existing `shared-local` debrunners may use exact dependency-wheel fixtures
without credentials. Preserve immutable candidate upload before validation and
post-validation digest checks. No tags, publication or merges during preparation.

Use the existing `shared-local` runner group with `[self-hosted, linux, x64, debrunner]`
for CI, admission and publication. Do not introduce GitHub-hosted runner jobs.
