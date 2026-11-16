# ACL runtime legal review

This review records the runtime built from the maintained Dockerfile. It adds
no source archives, package upgrades, release tags or visibility changes.
The image carries legal texts and a small metadata report only; normal installed
Python modules remain runtime dependencies, not extra source bundles.

## Installed LGPL/MPL candidates

The first CI inventory reports these installed distribution terms:

| Distribution | Version | Installed license metadata |
| --- | --- | --- |
| certifi | 2026.10.23 | MPL-2.0 |
| jwcrypto | 1.6.1 | LGPL-3.0-or-later |
| orjson | 3.13.0 | MPL-2.0 AND (Apache-2.0 OR MIT) |
| psycopg | 3.3.7 | LGPL-3.0-only |
| psycopg-binary | 3.3.7 | LGPL-3.0-only |

The installed notice index preserves full legal texts and their hashes. The
runtime review links each exact package/version to its upstream PyPI record.
The offline CI replacement contract mounts recipient-modified Certifi,
JWCrypto, orjson and Psycopg modules, as well as byte-modified native extensions
and bundled libpq. Successful imports demonstrate that these installed paths
are replaceable. The unused native trailing markers preserve the ABI; this
contract does not prove arbitrary replacements are compatible or satisfy every
licensing obligation. It starts no service or database and uses no network.

## Base image

The first runtime inventory identifies 97 installed Debian binary packages,
17 common license texts, and CPython 3.13.18. Every Debian package must retain
its installed copyright file; the report records its hash, binary version,
source package/version and corresponding Debian source-page reference.
CPython's installed license is hashed with its exact upstream version reference.
The report is regenerated for each build, not used to pin moving TEST services.

This base contains GNU components as well as permissive components. Notable
source families include glibc, gcc-12, libxcrypt, gnutls28, nettle, gmp, readline,
bash and coreutils. Consult their package-specific copyright files and the
preserved common license texts; do not treat the entire base as Apache-2.0 or
assume that a library's terms are those of its importing Python package.
Node and SociACL/Cargo notices remain covered by the preceding notice review.

The all-layer CI check rejects the known source-bundle directories, Debian
source archives and non-directory content under `/usr/src`, including content
hidden by later deletion. An empty base-image `/usr/src` directory is allowed.
No image-layer contents are extracted or executed by this scan.

## References and limits

- [LGPL 3.0, section 4](https://www.gnu.org/licenses/lgpl-3.0.html): combined-work and shared-library provisions.
- [MPL 2.0, section 3.2](https://www.mozilla.org/en-US/MPL/2.0/): executable distribution and source-availability provisions.
- [Debian policy, copyright information](https://www.debian.org/doc/debian-policy/ch-docs.html#copyright-information): installed copyright and common-license files.

Upstream references identify where to inspect corresponding versions. They are
not a source offer, a guarantee of continued availability, or a declaration of
legal compliance. This review preserves notice/provenance information and tests
replacement mechanics; it does not declare public distribution cleared. Source
archives must not be added to containers as a follow-up. Retained-image review
and the previously recorded historical-content restrictions remain separate.
