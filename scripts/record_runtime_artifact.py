"""Record a qualified local Docker archive; this is not registry provenance."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


def record(archive, image_id, revision, run_id, attempt):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('Invalid qualified image ID')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Invalid source revision')
    if run_id < 1 or attempt < 1:
        raise ValueError('Invalid Actions run identity')
    archive = Path(archive)
    with tarfile.open(archive, 'r:') as saved:
        members = saved.getmembers()
        if len({m.name for m in members}) != len(members):
            raise ValueError('Duplicate archive entries')

        def read_json(name):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive member path')
            member = saved.getmember(name)
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError('Invalid archive metadata member')
            raw = saved.extractfile(member).read()
            return raw, json.loads(raw)

        _, manifest = read_json('manifest.json')
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('Expected exactly one saved image')
        raw, config = read_json(manifest[0]['Config'])
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != image_id:
            raise ValueError('Archive differs from the qualified image ID')
        if (config.get('os'), config.get('architecture')) != ('linux', 'amd64'):
            raise ValueError('Unexpected qualified runtime platform')
        labels = config.get('config', {}).get('Labels', {})
        if labels.get('org.opencontainers.image.revision') != revision:
            raise ValueError('Image source differs from the Actions revision')
        if labels.get('org.opencontainers.image.source') != 'https://github.com/hyperme-sh/acl-service':
            raise ValueError('Image owner differs from ACL')
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {
        'schema_version': 1,
        'repository': 'hyperme-sh/acl-service',
        'revision': revision,
        'run_id': run_id,
        'run_attempt': attempt,
        'platform': 'linux/amd64',
        'image_config_digest': image_id,
        'archive': {'name': archive.name, 'sha256': digest, 'size': archive.stat().st_size},
        'qualification': 'Local image checks passed before archive upload; not a registry manifest digest, release, or deployment acceptance.',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = record(args.archive, args.image_id, args.revision, args.run_id, args.attempt)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
