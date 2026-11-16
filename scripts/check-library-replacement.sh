#!/usr/bin/env bash
# CI-only import contracts: no service, database or external network is started.
set -euo pipefail
image=${1:?Prepared image required}
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/acl-replacement.XXXXXX")
container=
cleanup() { if [[ -n "$container" ]]; then docker rm "$container" >/dev/null; fi; rm -rf -- "$scratch"; }
trap cleanup EXIT
container=$(docker create "$image")
site=/opt/venv/lib/python3.13/site-packages
docker cp "$container:$site/certifi" "$scratch/certifi"
docker cp "$container:$site/psycopg_binary.libs" "$scratch/psycopg_binary.libs"
# A synthetic added marker demonstrates that the loader accepts recipient edits.
printf '\nreplacement_contract_marker = True\n' >> "$scratch/certifi/__init__.py"
# An unused trailing marker preserves the library ABI while changing its bytes.
python3 - "$scratch" <<'PY'
from pathlib import Path
import sys
library, = (Path(sys.argv[1]) / 'psycopg_binary.libs').glob('libpq-*.so.*')
with library.open('ab') as stream:
    stream.write(b'\0recipient-replacement-contract\0')
PY
chmod -R a+rX "$scratch"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$scratch/certifi,dst=$site/certifi,readonly" \
  --mount "type=bind,src=$scratch/psycopg_binary.libs,dst=$site/psycopg_binary.libs,readonly" \
  --entrypoint /opt/venv/bin/python "$image" -I -c \
  'import certifi, psycopg; assert certifi.replacement_contract_marker; assert psycopg.pq.__impl__ == "binary"; assert psycopg.pq.version() >= 180000; print("Modified certifi package and ABI-compatible native library loaded")'
