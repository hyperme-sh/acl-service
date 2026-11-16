# ACL notices and history review

ACL remains Apache-2.0, version 0.1.0. Original and rebuilt wheels check the
owner LICENSE and NOTICE against the maintained files.

The runtime preserves installed Python legal texts and an index under
`/usr/share/acl-service/notices/python`. Exact upstream supplements fill missing
legal texts and incorporated GPL terms; they do not contain source archives.
The older Auth dependency has no LICENSE at its locked revision. Its supplement
records the later license-bearing owner revision: all original runtime lines
remain present, with 13 added lines in `token_validation.py` and other runtime
files identical. Installed bytes are hash-bound; historical publication remains
uncleared.
Missing installed texts or changed supplemental versions/hashes fail the build.
Node package legal texts remain beside their installed modules, indexed by
`/opt/acl-admission/npm-notices.json`. The Node 24.15.0 upstream LICENSE is
preserved separately. Native SociACL and fetched Cargo dependency legal texts
are retained with the build lockfile; this includes build dependencies, so the
collection is not a claim that every listed crate is linked into the library.
Debian copyright files remain in the base image. The separate
[runtime legal review](runtime-legal-review.md) records the installed LGPL/MPL
candidates, offline replacement contracts and base-image inventory, including
the limits of those checks.

Read-only history review covers fetched origin branches, tags and HEAD,
including bounded archived wheel members. The initial scan examined 1,850
objects and found 93 hosted-content coordinates: 49 in archived database wheels
and 44 in Core wheels. The hash-bound ledger retains them as not cleared for
publication. No historical code is executed. Deleted/unreachable refs, remote
LFS bytes and external archives are outside this scan. Secret matches require
exact-object/line classification; unexpected matches fail CI without printing
secret contents. A clean automated scan is not general publication clearance.

The [retained-image review](retained-image-review.md) records four initial
images and their hosted-content findings. ACL #197 owns neutral dependency
cleanup; retained images remain uncleared. No source bundles, settings
or visibility changes, history rewrites, dependency upgrades or manual releases
are introduced. GHCR TEST remains moving and integration/e2e stays nightly.
