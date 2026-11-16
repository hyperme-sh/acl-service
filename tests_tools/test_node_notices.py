import hashlib
import json
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/prepare_node_notices.mjs'

@pytest.mark.parametrize('change', ['none', 'version', 'digest', 'source', 'missing'])
def test_npm_supplements_bind_exact_installed_package(tmp_path, change):
    package = tmp_path / 'node_modules/example'
    package.mkdir(parents=True)
    (package / 'package.json').write_text(json.dumps({'name':'example','version':'1.0'}))
    (tmp_path / 'package-lock.json').write_text(json.dumps({'packages':{'node_modules/example':{'resolved':'https://example.invalid/exact.tgz'}}}))
    supplement = tmp_path / 'supplements/example'
    supplement.mkdir(parents=True)
    data = b'MIT fixture terms'
    (supplement / 'LICENSE').write_bytes(data)
    record = {'name':'example','version':'1.0','resolved':'https://example.invalid/exact.tgz','sha256':hashlib.sha256(data).hexdigest()}
    if change == 'version': record['version']='2.0'
    if change == 'digest': record['sha256']='0'*64
    if change == 'source': record['resolved']='https://example.invalid/other.tgz'
    (supplement / 'source.json').write_text(json.dumps(record))
    if change == 'missing':
        for p in supplement.iterdir(): p.unlink()
        supplement.rmdir()
    result = subprocess.run(['node',str(SCRIPT),'node_modules','index.json','supplements'],cwd=tmp_path,capture_output=True,text=True)
    assert (result.returncode == 0) == (change == 'none'), result.stderr
    if change == 'none':
        row, = json.loads((tmp_path/'index.json').read_text())
        assert row['texts'][0]['sha256'] == hashlib.sha256(data).hexdigest()
        assert (package/'LICENSE.upstream').read_bytes() == data
