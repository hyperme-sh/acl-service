import hashlib
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import prepare_runtime_artifact as prepare
import record_runtime_artifact as recorder
from test_runtime_artifact import archive, REVISION


@pytest.fixture
def qualified(tmp_path):
    tar, image_id = archive(tmp_path)
    receipt = recorder.record(tar, image_id, REVISION, 123, 1)
    path = tmp_path / 'artifact.zip'
    with zipfile.ZipFile(path, 'w') as output:
        output.write(tar, 'runtime.docker.tar')
        output.writestr('runtime-provenance.json', json.dumps(receipt))
    run = {'id': 123, 'head_sha': REVISION, 'repository': {'id': 7, 'full_name': prepare.REPOSITORY},
           'head_repository': {'full_name': prepare.REPOSITORY}, 'event': 'push', 'head_branch': 'main',
           'path': '.github/workflows/package.yml', 'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
    artifact = {'id': 456, 'name': 'tested-runtime', 'expired': False,
                'size_in_bytes': path.stat().st_size,
                'digest': 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest(),
                'workflow_run': {'id': 123, 'head_sha': REVISION, 'head_branch': 'main',
                                 'repository_id': 7, 'head_repository_id': 7}}
    jobs = [{'id': n, 'name': name, 'status': 'completed', 'conclusion': 'success'}
            for n, name in enumerate(sorted(prepare.REQUIRED_JOBS), 1)]
    return path, run, artifact, jobs


def stage(qualified, output):
    path, run, artifact, jobs = qualified
    return prepare.stage(path, output, run, artifact, jobs, 123, 456, REVISION)


def test_stages_only_verified_files_with_preparation_receipt(qualified, tmp_path):
    output = tmp_path / 'prepared'
    proof = stage(qualified, output)
    assert proof['status'] == 'prepared-only'
    assert proof['artifact_id'] == 456
    assert set(proof['checks']) == prepare.REQUIRED_JOBS
    assert {p.name for p in output.iterdir()} == {'runtime.docker.tar', 'runtime-provenance.json', 'preparation.json'}
    with pytest.raises(ValueError, match='already exists'):
        stage(qualified, output)


@pytest.mark.parametrize('field,value', [('head_sha', 'b' * 40), ('event', 'workflow_dispatch'),
    ('head_branch', 'feature'), ('path', '.github/workflows/other.yml'), ('conclusion', 'failure'),
    ('status', 'in_progress'), ('run_attempt', 0)])
def test_rejects_wrong_or_unqualified_run(qualified, tmp_path, field, value):
    qualified[1][field] = value
    with pytest.raises(ValueError):
        stage(qualified, tmp_path / 'prepared')
    assert not (tmp_path / 'prepared').exists()


def test_fork_origin_is_not_qualified(qualified, tmp_path):
    qualified[1]['head_repository']['full_name'] = 'other/acl-service'
    with pytest.raises(ValueError, match='repository'):
        stage(qualified, tmp_path / 'prepared')


@pytest.mark.parametrize('field,value', [('id', 457), ('name', 'tested-dist'), ('expired', True),
    ('digest', None), ('size_in_bytes', prepare.MAX_ARCHIVE + 1)])
def test_rejects_wrong_expired_or_unbound_artifact(qualified, tmp_path, field, value):
    qualified[2][field] = value
    with pytest.raises(ValueError):
        stage(qualified, tmp_path / 'prepared')


def test_rejects_artifact_from_another_source(qualified, tmp_path):
    qualified[2]['workflow_run']['head_sha'] = 'b' * 40
    with pytest.raises(ValueError, match='origin'):
        stage(qualified, tmp_path / 'prepared')


@pytest.mark.parametrize('kind', ['missing', 'failed', 'duplicate'])
def test_requires_unique_successful_replay(qualified, tmp_path, kind):
    jobs = qualified[3]
    replay = next(job for job in jobs if job['name'] == 'runtime-replay')
    if kind == 'missing':
        jobs.remove(replay)
    elif kind == 'failed':
        replay['conclusion'] = 'failure'
    else:
        jobs.append(dict(replay))
    with pytest.raises(ValueError, match='runtime-replay'):
        stage(qualified, tmp_path / 'prepared')


def test_changed_download_fails_before_staging(qualified, tmp_path):
    path = qualified[0]
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(ValueError, match='digest mismatch'):
        stage(qualified, tmp_path / 'prepared')


@pytest.mark.parametrize('kind', ['traversal', 'symlink', 'receipt-run'])
def test_invalid_authenticated_payload_does_not_escape_staging(qualified, tmp_path, kind):
    path, _, artifact, _ = qualified
    with zipfile.ZipFile(path) as original:
        tar = original.read('runtime.docker.tar')
        receipt = json.loads(original.read('runtime-provenance.json'))
    with zipfile.ZipFile(path, 'w') as changed:
        if kind == 'traversal':
            changed.writestr('../escape', tar)
        elif kind == 'symlink':
            member = zipfile.ZipInfo('runtime.docker.tar')
            member.create_system = 3
            member.external_attr = 0o120777 << 16
            changed.writestr(member, 'outside')
        else:
            changed.writestr('runtime.docker.tar', tar)
            receipt['run_id'] = 124
        changed.writestr('runtime-provenance.json', json.dumps(receipt))
    artifact['digest'] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
    artifact['size_in_bytes'] = path.stat().st_size
    with pytest.raises(ValueError):
        stage(qualified, tmp_path / 'prepared')
    assert not (tmp_path / 'prepared').exists()
    assert not (tmp_path.parent / 'escape').exists()
