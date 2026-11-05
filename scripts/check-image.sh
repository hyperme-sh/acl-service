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
