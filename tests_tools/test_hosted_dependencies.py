import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from assert_no_hosted_dependencies import verify


@pytest.mark.parametrize('path,data', [
    ('stripe/__init__.py', b''),
    ('api/domain/dtos/billing_dto.py', b''),
    ('api/core/container.py', b'import stripe'),
    ('example.dist-info/METADATA', b'Requires-Dist: stripe>=16\n'),
])
def test_deleted_lower_layer_hosted_code_rejected(tmp_path, path, data):
    def add(archive, name, content):
        entry = tarfile.TarInfo(name)
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    image = tmp_path / 'image.tar'
    with tarfile.open(image, 'w') as outer:
        add(outer, 'manifest.json', json.dumps([{'Layers': ['old.tar', 'new.tar']}]).encode())
        for filename, name, content in [
            ('old.tar', path, data), ('new.tar', '.wh.' + path.split('/')[0], b'')
        ]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as layer:
                add(layer, 'opt/venv/lib/python3.13/site-packages/' + name, content)
            add(outer, filename, stream.getvalue())
    with pytest.raises(ValueError, match='Hosted|Provider'):
        verify(image)
