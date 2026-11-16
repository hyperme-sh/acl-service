#!/usr/bin/env bash
set -euo pipefail
image=${1:?Qualified image required}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
docker image save "$image" -o "$scratch/image.tar"
python3 scripts/assert_no_source_bundles.py "$scratch/image.tar"
