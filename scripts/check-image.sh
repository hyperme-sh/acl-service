#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=${1:?Pass the locally built image tag or digest}
# Compare installed runtime bytes to the maintained package, not a historical tree.
python3 - "$image" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path('src/acl_service')
expected = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
code = '''import hashlib,json,pathlib,acl_service
root=pathlib.Path(acl_service.__file__).parent
assert str(root).startswith('/opt/venv/'), str(root)
print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}))'''
actual = json.loads(subprocess.check_output(['docker', 'run', '--rm', '--network', 'none',
                    sys.argv[1], 'python', '-I', '-c', code], text=True))
assert actual == expected, 'Image runtime differs from maintained package'
print('Image imports the exact maintained package bytes')
PY
docker run --rm --network none --read-only --tmpfs /tmp \
  --mount "type=bind,src=$PWD/tests/container_http.py,dst=/checks/container_http.py,readonly" \
  "$image" python -I /checks/container_http.py

# Exercise the image-owned writer offline, with only public test vectors on stdin.
python3 - <<'PY' | docker run --rm -i --read-only --network none --tmpfs /tmp "$image" python -I -c '
import json, sys
from pathlib import Path
sys.path.insert(0, "/opt/acl-admission")
from history_admission import EnrollmentGrant, HistoryAdmission
from acl_service.infrastructure.sqlite_history_store import SqliteHistoryStore
f, operations = json.load(sys.stdin)
p = f["genesis"]
grant = EnrollmentGrant(p, "qualification", "one-use-grant", f["now"] + 60)
writer = HistoryAdmission(SqliteHistoryStore(Path("/tmp/history.sqlite")), grant_for=lambda _: grant,
                          trust_at=lambda _: {k: f[k] for k in ("policy","jwks","pinnedIss")}, clock=lambda: f["now"])
writer.enroll(p, json.dumps(f["binding"]).encode(), f["signature"])
assert writer.apply_store_operation(p, "recovery", operations["current"]) == 1
assert writer.apply_store_operation(p, "wraps", operations["wrap"]) == 1
'
import json
from pathlib import Path
print(json.dumps([json.loads(path.read_bytes()) for path in
                  (Path("admission/fixture.json"), Path("admission/store-fixture.json"))]))
PY
