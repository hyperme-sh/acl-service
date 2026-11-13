"""Stage a GitHub-qualified ACL runtime without loading, publishing or deploying it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from record_runtime_artifact import verify

REPOSITORY = 'hyperme-sh/acl-service'
MAX_ARCHIVE = 1024 * 1024 * 1024
REQUIRED_JOBS = {'source', 'package', 'image', 'runtime-replay'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(path):
    raw = subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}'], timeout=60)
    return json.loads(raw)


def metadata(run, artifact, jobs, run_id, artifact_id, revision):
    require(type(run_id) is int and run_id > 0 and type(artifact_id) is int and artifact_id > 0,
            'Positive run and artifact IDs required')
    require(re.fullmatch(r'[0-9a-f]{40}', revision), 'Exact source revision required')
    require(run['id'] == run_id and run['head_sha'] == revision, 'Run source mismatch')
    require(run['repository']['full_name'] == REPOSITORY
            and run['head_repository']['full_name'] == REPOSITORY, 'Wrong run repository')
    require(run['event'] == 'push' and run['head_branch'] == 'main'
            and run['path'] == '.github/workflows/package.yml', 'Not owning main qualification')
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'Run is not successful')
    require(type(run['run_attempt']) is int and run['run_attempt'] > 0, 'Invalid run attempt')
    require(artifact['id'] == artifact_id and artifact['name'] == 'tested-runtime'
            and artifact['expired'] is False, 'Wrong or expired runtime artifact')
    origin = artifact['workflow_run']
    require(origin['id'] == run_id and origin['head_sha'] == revision
            and origin['head_branch'] == 'main'
            and origin['repository_id'] == run['repository']['id']
            and origin['head_repository_id'] == run['repository']['id'], 'Artifact origin mismatch')
    require(isinstance(artifact.get('digest'), str)
            and re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']), 'Missing artifact digest')
    require(type(artifact['size_in_bytes']) is int and 0 < artifact['size_in_bytes'] <= MAX_ARCHIVE,
            'Artifact size outside preparation limit')
    for name in REQUIRED_JOBS:
        matches = [job for job in jobs if job['name'] == name]
        require(len(matches) == 1 and matches[0]['status'] == 'completed'
                and matches[0]['conclusion'] == 'success', f'Missing successful {name} job')


def stage(archive, output, run, artifact, jobs, run_id, artifact_id, revision):
    metadata(run, artifact, jobs, run_id, artifact_id, revision)
    archive, output = Path(archive), Path(output)
    require(not output.exists(), 'Output directory already exists')
    require(archive.stat().st_size == artifact['size_in_bytes'], 'Downloaded archive size mismatch')
    with archive.open('rb') as source:
        digest = 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()
    require(digest == artifact['digest'], 'Downloaded artifact digest mismatch')
    with tempfile.TemporaryDirectory(dir=output.parent, prefix='.acl-runtime-') as temporary:
        root = Path(temporary) / 'verified'
        root.mkdir()
        with zipfile.ZipFile(archive) as saved:
            members = saved.infolist()
            require(len(members) == 2 and {m.filename for m in members}
                    == {'runtime.docker.tar', 'runtime-provenance.json'}, 'Unexpected artifact members')
            for member in members:
                require((member.external_attr >> 16) & 0o170000 in (0, 0o100000), 'Non-regular artifact member')
                limit = MAX_ARCHIVE if member.filename == 'runtime.docker.tar' else 1024 * 1024
                require(0 < member.file_size <= limit, 'Expanded artifact member exceeds limit')
                with saved.open(member) as source, (root / member.filename).open('xb') as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
        receipt_path = root / 'runtime-provenance.json'
        receipt = json.loads(receipt_path.read_text())
        # Only after the whole archive matches GitHub's digest is this receipt
        # authenticated as output of the explicitly selected successful run.
        verified = verify(root / 'runtime.docker.tar', receipt_path,
                          receipt['image_id'], revision, run_id, run['run_attempt'],
                          receipt['archive']['sha256'])
        proof = {'schema_version': 1, 'status': 'prepared-only', 'repository': REPOSITORY,
                 'revision': revision, 'run_id': run_id, 'run_attempt': run['run_attempt'],
                 'artifact_id': artifact_id, 'artifact_digest': digest,
                 'image_id': verified['image_id'], 'image_config_digest': verified['image_config_digest'],
                 'archive_sha256': verified['archive']['sha256'],
                 'checks': {job['name']: job['id'] for job in jobs if job['name'] in REQUIRED_JOBS},
                 'scope': 'Verified local preparation only; no registry publication or live deployment acceptance.'}
        (root / 'preparation.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
        root.rename(output)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--artifact-id', type=int, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive-zip', type=Path, help='Reuse a download; still verify it against live GitHub metadata')
    args = parser.parse_args()
    require(args.run_id > 0 and args.artifact_id > 0, 'Positive run and artifact IDs required')
    require(re.fullmatch(r'[0-9a-f]{40}', args.revision), 'Exact source revision required')
    run = api(f'actions/runs/{args.run_id}')
    artifact = api(f'actions/artifacts/{args.artifact_id}')
    jobs = []
    for page in range(1, 11):
        batch = api(f'actions/runs/{args.run_id}/attempts/{run["run_attempt"]}/jobs?per_page=100&page={page}')['jobs']
        jobs.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError('Qualification job inventory exceeds limit')
    metadata(run, artifact, jobs, args.run_id, args.artifact_id, args.revision)
    with tempfile.TemporaryDirectory(prefix='acl-runtime-download-') as temporary:
        archive = args.archive_zip or Path(temporary) / 'artifact.zip'
        if not args.archive_zip:
            with archive.open('xb') as target:
                subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}/zip'],
                               stdout=target, check=True, timeout=180)
        proof = stage(archive, args.output, run, artifact, jobs, args.run_id, args.artifact_id, args.revision)
    print(json.dumps(proof, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
