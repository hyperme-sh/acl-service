import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location('runtime_artifact', Path(__file__).parents[1] / 'scripts/record_runtime_artifact.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
REVISION = 'a' * 40


def archive(tmp_path, *, revision=REVISION, config_path='blobs/sha256/config', duplicate=False, images=1, architecture='amd64'):
    config = json.dumps({'os': 'linux', 'architecture': architecture, 'config': {'Labels': {
        'org.opencontainers.image.revision': revision,
        'org.opencontainers.image.source': 'https://github.com/hyperme-sh/acl-service'}}}).encode()
    image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
    destination = tmp_path / 'runtime.docker.tar'
    entries = [('manifest.json', json.dumps([{'Config': config_path, 'RepoTags': None, 'Layers': []}] * images).encode()), (config_path, config)]
    if duplicate:
        entries.append(entries[-1])
    with tarfile.open(destination, 'w') as saved:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            saved.addfile(member, io.BytesIO(data))
    return destination, image_id


def test_receipt_binds_exact_archive_and_qualified_image(tmp_path):
    path, image_id = archive(tmp_path)
    receipt = module.record(path, image_id, REVISION, 123, 2)
    assert receipt['archive']['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert receipt['archive']['size'] == path.stat().st_size
    assert receipt['image_config_digest'] == image_id
    assert receipt['revision'] == REVISION
    assert (receipt['run_id'], receipt['run_attempt']) == (123, 2)
    assert 'registry manifest digest' in receipt['qualification']


def test_archive_cannot_substitute_another_image(tmp_path):
    path, _ = archive(tmp_path)
    with pytest.raises(ValueError, match='qualified image ID'):
        module.record(path, 'sha256:' + '0' * 64, REVISION, 123, 1)


@pytest.mark.parametrize('options,message', [
    ({'revision': 'b' * 40}, 'source differs'),
    ({'architecture': 'arm64'}, 'platform'),
    ({'duplicate': True}, 'Duplicate'),
    ({'config_path': '../config'}, 'Unsafe'),
    ({'images': 2}, 'exactly one'),
])
def test_rejects_ambiguous_or_wrong_runtime(tmp_path, options, message):
    path, image_id = archive(tmp_path, **options)
    with pytest.raises(ValueError, match=message):
        module.record(path, image_id, REVISION, 123, 1)


@pytest.mark.parametrize('revision,run_id,attempt', [('main', 1, 1), (REVISION, 0, 1), (REVISION, 1, 0)])
def test_requires_exact_source_and_run_identity(tmp_path, revision, run_id, attempt):
    path, image_id = archive(tmp_path)
    with pytest.raises(ValueError):
        module.record(path, image_id, revision, run_id, attempt)
