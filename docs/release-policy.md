# Release compatibility

This component targets the shared **0.24.x** release line. Components share major
and minor versions; patch numbers advance independently while preserving their
accepted API contracts. `release-policy.json` identifies the owner and owning
package version files.

## Published stable baseline

[v0.24.0](https://github.com/hyperme-sh/acl-service/releases/tag/v0.24.0) is the
first immutable stable distribution. `releases/accepted` binds its actual GitHub
release ID, tag source and asset digests. The wheel and source distribution match
main validation run 42034389382 byte-for-byte. Exact-tag initial admission
42034791412 and publication 42034791540 passed.

Historical test receipts remain under `releases/qualification`. They do not
reserve stable versions and must never become accepted baselines. Main merges
retain qualification artifacts in Actions; they do not publish GitHub releases.

## Subsequent releases

1. Select the verified stable record independently using the repository variable
   `SPANOPTICON_RELEASE_BASELINE_SHA`. It must identify a full commit containing
   the accepted record; candidate data cannot select its own baseline.
2. Generate `releases/candidate/release.json` and its contract from the actual
   package. Owning metadata, release line, requested version, contract and wheel
   digest must match. A published version cannot acquire different artifact bytes.
3. Merge the candidate and qualify that exact main source. Source, fresh wheel,
   rebuilt sdist, disposable PostgreSQL and image checks must pass. Preserve the
   original Actions artifact for promotion; missing or expired evidence fails.
4. Push the matching stable version tag at the qualified commit. Both inline
   automated admission and the independent publisher validate the release. The
   publisher promotes the original files without rebuilding, then verifies the
   immutable release and provenance.
5. Verify published bytes, record the actual stable provenance, and advance the
   independently selected baseline. A package release does not establish service
   deployment or coordinated provider/consumer acceptance.

The initial-admission path is only for an owner with no stable release and no
selected baseline. It checks complete live history and binds the explicit
candidate to the exact main artifact. ACL has now completed that bootstrap;
missing accepted baseline selection cannot substitute for subsequent admission.

Retries of immutable publication verify original evidence and preserve assets.
The publication workflow retains its automated admission prerequisite, so its
baseline must stay configured after bootstrap. Configuration-only PR checks are
not release compatibility evidence.

Private jobs use debrunners. The pinned publisher provisions managed Python 3.12
through uv without loading caller project configuration or executing caller code.
Publication receives only its repository-scoped contents-write/actions-read token;
validation and deployment credentials stay separate.

No required reviewers, branch protections, approval rulesets, environment
approvals, CODEOWNERS approval requirements or human release/deployment gates
are required. See the [shared policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md)
for the manifest format and compatibility rules.
