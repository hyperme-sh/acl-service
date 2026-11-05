# Preparing a retained ACL runtime

Preparation stages the already-qualified Docker archive. It does not load the
image, contact service dependencies, change infrastructure, publish a registry
image, create a version tag, or publish a release. Tag/release actions still need
the user's explicit approval. No GitHub reviewer or branch-protection settings
are needed.

## Verified starting point

Main run [42044558890](https://github.com/hyperme-sh/acl-service/actions/runs/42044558890)
at `8dd6d1a8d3009601cd065ee10e2b53a7e8757ca7` passed candidate, source, package,
image and independent runtime-replay checks. Its `tested-runtime` artifact ID is
`13422987993`; GitHub's ZIP digest is
`sha256:d59c7b048243f91054175afeb6daa2853128da5a274efb01eed3edee8d07c9f6`.
The retained archive was downloaded, digest-checked and successfully staged with
live run/artifact/job metadata. This is historical evidence, not an instruction
to select that source for deployment or a permanent artifact-retention promise.

## Read-only preparation

Use Python 3.11 or later and an authenticated GitHub CLI with read access to the
private repository and Actions artifacts. Select an exact successful main-push
run, artifact ID and full source SHA explicitly; no latest-release lookup occurs.
Run from the trusted ACL checkout containing the verifier, never from files
extracted from the artifact.

```sh
python3 scripts/prepare_runtime_artifact.py \
  --run-id RUN_ID --artifact-id ARTIFACT_ID --revision FULL_SOURCE_SHA \
  --output /tmp/acl-prepared-runtime
```

The output directory must not exist and its parent must exist. To reuse a ZIP
already downloaded from Actions, add `--archive-zip /path/to/artifact.zip`; this
still checks it against live GitHub metadata and the API digest.

The tool requires owning main-push qualification, exact source/artifact origin,
an unexpired digest-bound artifact, and successful candidate/source/package/image/
runtime-replay jobs. It verifies the ZIP before unpacking only the two expected
regular files. It then rechecks the runtime receipt, archive checksum, image
identity chain, source and producer attempt. Mixed-attempt evidence is rejected;
this first implementation requires a complete successful producer/replay attempt.
A missing or expired artifact cannot be replaced with a rebuild under old proof.

Output consists of `runtime.docker.tar`, `runtime-provenance.json`, and
`preparation.json`. The last file records the verified GitHub run/job/artifact
identities and explicitly says `prepared-only`. It is not authority to deploy,
publish or establish a stable baseline. The local image ID and config digest
remain distinct from registry publication evidence.

## Remaining test-deployment acceptance

The replay checks compare installed runtime bytes and exercise HTTP authorization
boundaries with synthetic dependencies. They deliberately do not enter the real
application lifespan, connect a database/event bus, or prove external token trust.

Before selecting an actual test runtime, prepare an isolated tenant/data scope,
the owning database and migration contract, verified auth/tenant configuration,
and the event publisher/user-created consumer configuration used by app startup.
Use existing infra/config secret delivery; do not embed credentials in the image,
archive or preparation record. Witness publication/keyring settings must retain
their existing trust boundaries and remain unconfigured unless intentionally tested.

Live acceptance must exercise startup/readiness, authenticated same-tenant
administration, cross-tenant and forged-identity rejection, durable policy effects,
and event processing using the selected runtime identity. A health response,
fixture replay or archive checksum alone does not close those gates. The owning
infra test target and any eventual registry publication/deployment adapter remain
separate work; this script performs none of them.
