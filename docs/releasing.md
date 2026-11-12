# Releasing acl-service

The package version in `pyproject.toml` is **0.1.0**. A GitHub Release is
published by the stable tag workflow below, using files already tested on
`main`. A main push by itself leaves the validated wheel and sdist as Actions
artifacts. Stable assets are GitHub release files. PyPI upload and service
deployment are separate pipelines.

Compatibility rules for admission live in
[Release compatibility](release-policy.md). The tag workflow pins the
Spanopticon component-release workflow and passes release line `0.1` plus the
repository variable `SPANOPTICON_RELEASE_BASELINE_SHA`. The shared publisher
contract is the
[release-channel action](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

## Main validation

`.github/workflows/package.yml` runs on every push to `main`.

The candidate job builds the wheel and sdist and uploads them as the
`tested-dist` artifact immediately, before repository validators or tests.
Source tests run in their own job. After those jobs pass, a separate job
downloads that artifact id and runs fresh-wheel and rebuilt-sdist checks on a
disposable copy. Expected hashes stay in the invoking shell and are checked
again after validation. The candidate upload happens once, before tests.
Later jobs only download that artifact id.

The publisher accepts a stable promotion only when the whole main-push
workflow succeeded, and it promotes only that immutable candidate. A failed
validation leaves the candidate unpublished.

To repeat those checks locally against a candidate that was already built, set
`RELEASE_CANDIDATE_DIR` to a directory that contains exactly that wheel and
source distribution, then run `bash scripts/check-package.sh`. Without the
variable, the script builds and tests the checkout as usual.

## Stable tag

Push `vMAJOR.MINOR.PATCH` at the tested commit.
`.github/workflows/release.yml` runs admission first. When admission succeeds,
the publisher job promotes the original main-push artifact without rebuilding.
Repository visibility applies to every release asset. Enable immutable
releases on the repository so a tag cannot swap bytes later.

Promotion needs that original Actions artifact. The workflow requests 90 days
of retention; organization policy may keep it for less. When the artifact is
gone, validate a new main revision and tag that commit. The publisher checks
the workflow run, the source revision, the workflow file, and the artifact
digest on its own. Release metadata is not enough.

## Qualification and a stable baseline

`test-<commit>` prereleases are development snapshots. The version embedded in
the wheel does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. A test receipt needs an explicit
non-stable classification. Package checks and artifact checks stay
separate from stable admission.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are for an actual
immutable stable GitHub Release. The shared guard checks the live release
channel, the stable tag's source, and the asset digests. A qualification
snapshot cannot become accepted by a provenance label. No baseline is recorded
until that release exists.

When no baseline is selected, admission validates the explicit candidate and
the repository's live release history. The publisher checks package metadata
and the exact tested bytes, then claims that initial source. Later releases
require a real stable baseline. Deployment and consumer acceptance of a
running service are separate from this package publication.

The manifests under `releases/qualification` bind the candidate wheel. The
sdist rebuild is checked against the same contract. PostgreSQL boundary checks
in the main package job are part of that qualification.

## Pull-request preparation

`.github/workflows/preparation.yml` uploads a preparation candidate before
repository validators, then downloads that same artifact id in a second job.
Source, fresh-wheel, and rebuilt-sdist consumers use the verified wheels built
from the exact Git pins. Expected hashes stay in the invoking shell and are
checked again. The validation job uploads evidence of the checks. The
package bytes stay the candidate uploaded earlier.

`bash scripts/check-package.sh --fixtures` is the same credential-free path on
a workstation. The fixture manifest records the clean source revisions and
digests. Those fixtures are not a published baseline. The retained artifact
counts as qualified only when both jobs pass. Tags, GitHub Releases, and
deployment stay on the main and tag workflows.

## Retained runtime image

A successful main image job keeps `tested-runtime` for 30 days (organization
retention can be shorter). The artifact contains `runtime.docker.tar` and
`runtime-provenance.json`. The receipt binds the archive checksum, the local
image id, the image config digest, the Linux/amd64 platform, the source
revision, and the Actions run and attempt. Export uses the immutable local
image id. The archive config digest and the source label are verified before
upload.

The receipt records the local image config digest. A registry manifest
digest, a GitHub Release, and a deployment are later steps.
`tested-dist` stays with the package publisher. Rebuild an expired archive
only as a new qualification. The rebuilt image is a new artifact.

The recorder accepts classic Docker config ids and containerd manifest and
index ids. For containerd it checks each referenced metadata digest and size
down to the saved config and selects one Linux/amd64 runtime. The local image
id and the config digest are stored separately.

The `runtime-replay` job downloads the artifact id from the image job. Before
it loads the archive it compares the archive and the receipt with the image
id, archive checksum, source revision, and Actions run and attempt that the
image job reported. Archives that contain repository tags are refused. The job
then loads the archive and repeats the network-isolated runtime checks without
dependency credentials. It also runs a startup check against disposable
PostgreSQL, the real application lifespan, readiness, rejection of missing and
malformed credentials, tenant-scoped policy creation, restart persistence, and
idempotent redelivery. Loaded images and temporary files are removed afterward.

Read-only retrieval and staging of a retained runtime is documented in
[Preparing a retained ACL runtime](runtime-preparation.md). That tool checks
live GitHub qualification evidence and stages the bytes for a later load.

Development package checks compare source, wheel, and rebuilt source-archive
contents and test the fresh immutable candidate produced by CI. Historical files
under `releases/qualification` remain historical records; their wheel digest is
not the expected digest of every future development build. Tag-context checks,
or an explicit `VERIFY_RELEASE_CANDIDATE=1`, additionally bind the build to
`releases/candidate/release.json` with the existing exact-byte verifier. A missing
or mismatched declared candidate still fails. Stable publication retains its
independent shared admission workflow and explicit version authorization.
