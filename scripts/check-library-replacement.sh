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
docker cp "$container:$site/jwcrypto" "$scratch/jwcrypto"
docker cp "$container:$site/orjson" "$scratch/orjson"
docker cp "$container:$site/psycopg" "$scratch/psycopg"
docker cp "$container:$site/psycopg_binary" "$scratch/psycopg_binary"
docker cp "$container:$site/certifi" "$scratch/certifi"
docker cp "$container:$site/psycopg_binary.libs" "$scratch/psycopg_binary.libs"
# A synthetic added marker demonstrates that the loader accepts recipient edits.
printf '\nreplacement_contract_marker = True\n' >> "$scratch/certifi/__init__.py"
printf '\nreplacement_contract_marker = True\n' >> "$scratch/psycopg/__init__.py"
printf '\nreplacement_contract_marker = True\n' >> "$scratch/jwcrypto/__init__.py"
printf '\nreplacement_contract_marker = True\n' >> "$scratch/orjson/__init__.py"
# An unused trailing marker preserves the library ABI while changing its bytes.
python3 - "$scratch" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
library, = (root / 'psycopg_binary.libs').glob('libpq-*.so.*')
extensions = list((root / 'psycopg_binary').glob('*.so'))
assert extensions, 'Missing LGPL native extension'
orjson_extensions = list((root / 'orjson').glob('*.so'))
assert orjson_extensions, 'Missing orjson native extension'
extensions.extend(orjson_extensions)
for path in [library, *extensions]:
    with path.open('ab') as stream:
        stream.write(b'\0recipient-replacement-contract\0')
PY
chmod -R a+rX "$scratch"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$scratch/jwcrypto,dst=$site/jwcrypto,readonly" \
  --mount "type=bind,src=$scratch/orjson,dst=$site/orjson,readonly" \
  --mount "type=bind,src=$scratch/psycopg,dst=$site/psycopg,readonly" \
  --mount "type=bind,src=$scratch/psycopg_binary,dst=$site/psycopg_binary,readonly" \
  --mount "type=bind,src=$scratch/certifi,dst=$site/certifi,readonly" \
  --mount "type=bind,src=$scratch/psycopg_binary.libs,dst=$site/psycopg_binary.libs,readonly" \
  --entrypoint /opt/venv/bin/python "$image" -I -c \
  'import certifi, psycopg, jwcrypto, orjson; assert jwcrypto.replacement_contract_marker and orjson.replacement_contract_marker; assert orjson.loads(orjson.dumps({"contract": True}))["contract"]; assert certifi.replacement_contract_marker and psycopg.replacement_contract_marker; assert psycopg.pq.__impl__ == "binary"; assert psycopg.pq.version() >= 180000; print("Modified Certifi, JWCrypto, orjson and Psycopg packages and native libraries loaded")'
