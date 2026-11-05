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


def archive(tmp_path, *, revision=REVISION, config_path='blobs/sha256/config', duplicate=False, images=1, architecture='amd64', tags=None):
    config = json.dumps({'os': 'linux', 'architecture': architecture, 'config': {'Labels': {
        'org.opencontainers.image.revision': revision,
        'org.opencontainers.image.source': 'https://github.com/hyperme-sh/acl-service'}}}).encode()
    image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
    destination = tmp_path / 'runtime.docker.tar'
    entries = [('manifest.json', json.dumps([{'Config': config_path, 'RepoTags': tags, 'Layers': []}] * images).encode()), (config_path, config)]
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
    ({'tags': ['example:version']}, 'Tagged runtime'),
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


def containerd_archive(tmp_path, *, root_kind='index', damage=False, duplicate_platform=False):
    path, config_digest = archive(tmp_path)
    with tarfile.open(path) as saved:
        config = saved.extractfile('blobs/sha256/config').read()
    config_path = 'blobs/sha256/' + config_digest.split(':')[1]
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': {'digest': config_digest, 'size': len(config)}, 'layers': []}).encode()
    manifest_digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
    descriptor = {'digest': manifest_digest, 'size': len(manifest), 'platform': {'os': 'linux', 'architecture': 'amd64'}}
    index = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
        'manifests': [descriptor] * (2 if duplicate_platform else 1) + [
            {'platform': {'os': 'unknown', 'architecture': 'unknown'}, 'digest': 'sha256:' + '0' * 64}]}).encode()
    index_digest = 'sha256:' + hashlib.sha256(index).hexdigest()
    entries = [('manifest.json', json.dumps([{'Config': config_path, 'RepoTags': None}]).encode()),
               (config_path, config),
               ('blobs/sha256/' + manifest_digest.split(':')[1], manifest + (b' ' if damage else b'')),
               ('blobs/sha256/' + index_digest.split(':')[1], index)]
    with tarfile.open(path, 'w') as saved:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            saved.addfile(member, io.BytesIO(data))
    return path, index_digest if root_kind == 'index' else manifest_digest, config_digest


@pytest.mark.parametrize('root_kind', ['index', 'manifest'])
def test_containerd_identity_binds_manifest_to_distinct_config(tmp_path, root_kind):
    path, image_id, config_digest = containerd_archive(tmp_path, root_kind=root_kind)
    receipt = module.record(path, image_id, REVISION, 123, 1)
    assert receipt['image_id'] == image_id
    assert receipt['image_config_digest'] == config_digest
    assert image_id != config_digest


@pytest.mark.parametrize('options,message', [
    ({'damage': True}, 'content mismatch'),
    ({'duplicate_platform': True}, 'one Linux/amd64'),
])
def test_containerd_rejects_unbound_or_ambiguous_children(tmp_path, options, message):
    path, image_id, _ = containerd_archive(tmp_path, **options)
    with pytest.raises(ValueError, match=message):
        module.record(path, image_id, REVISION, 123, 1)


def test_replay_rejects_archive_or_run_substitution(tmp_path):
    path, image_id = archive(tmp_path)
    receipt = tmp_path / 'runtime-provenance.json'
    receipt.write_text(json.dumps(module.record(path, image_id, REVISION, 123, 2)))
    expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    module.verify(path, receipt, image_id, REVISION, 123, 2, expected_digest)
    with pytest.raises(ValueError, match='expected workflow identity'):
        module.verify(path, receipt, image_id, REVISION, 124, 2, expected_digest)
    with path.open('ab') as output:
        output.write(b'\0' * 512)
    with pytest.raises(ValueError, match='expected workflow identity'):
        module.verify(path, receipt, image_id, REVISION, 123, 2, expected_digest)


def test_receipt_cannot_replace_the_independently_expected_checksum(tmp_path):
    path, image_id = archive(tmp_path)
    trusted_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open('ab') as output:
        output.write(b'\0' * 512)
    receipt = tmp_path / 'runtime-provenance.json'
    receipt.write_text(json.dumps(module.record(path, image_id, REVISION, 123, 2)))
    with pytest.raises(ValueError, match='Archive checksum differs'):
        module.verify(path, receipt, image_id, REVISION, 123, 2, trusted_digest)
