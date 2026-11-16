# ACL retained-image and historical-content review

The initial authenticated inventory found four retained GHCR runtime images,
including tagged and untagged versions. The digest-bound records in
[retained-images.json](retained-images.json) identify the inspected bytes and
link the CI jobs. The images have 12, 12, 16 and 17 layers; each declares runtime
user `10001:10001`. Static inspection found no source-bundle paths or configured
Hypermesh/Conductor environment names in those retained layers.

Every image contains 1,759 hosted-content path occurrences, including bytecode,
from older Core/API dependencies and the Stripe SDK. Examples include billing
DTOs/endpoints, Stripe resolvers and service modules. This is not a claim that
all matching code is private or that it contains credentials. The images remain
retained and **not cleared for public distribution**. [ACL #197](https://github.com/hyperme-sh/acl-service/issues/197)
owns removing hosted dependencies from newly built images while preserving ACL
behavior. No old image is deleted, modified or republished by this review.

The source-history ledger still records 93 archived DB/Core coordinates as
retained and uncleared. This image review complements that record; successful
secret scans do not clear either category for publication.

CI inventories current tags and retained package versions, selects Linux amd64
manifests, verifies manifest digests and inspects every layer without running an
old image. Package API or registry failures cannot count as verified absence.
After automatic TEST publication, a separate inventory/review includes the newly
published image. No Actions archives are uploaded; output remains in CI logs.

Secret classifications recognize exact upstream Pydeck symbols, the public
CPython signing fingerprint, and exact Auth provenance file hashes in the
matching notice record. Unexpected matches fail without printing secret values.
Tests cover path traversal, retained lower-layer content, private inventory
failures and changed notice-hash classifications.

Limits: deleted registry versions, other registries/platforms and unreachable
Git refs are not covered. Hosted-content heuristics inspect installed Python
paths/content; they do not establish that every other file is public-safe.
Legal texts and source-bundle paths are observed across all layers, not only the
visible final filesystem. The review records a point-in-time inventory; future
main runs regenerate it. No visibility changes, history rewrites, source bundles,
manual releases or deployment pins are introduced. GHCR TEST stays moving and
integration/e2e remains nightly.
