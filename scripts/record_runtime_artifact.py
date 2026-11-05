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
        if manifest[0].get('RepoTags') not in (None, []):
            raise ValueError('Tagged runtime archives are not accepted for replay')
        raw, config = read_json(manifest[0]['Config'])
        config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        # Classic Docker IDs identify config bytes; containerd IDs can identify
        # an OCI manifest or index. Bind every descriptor before following it.
        def blob(digest, size=None):
            if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ValueError('Invalid image descriptor digest')
            content, document = read_json('blobs/sha256/' + digest.split(':')[1])
            if 'sha256:' + hashlib.sha256(content).hexdigest() != digest:
                raise ValueError('Image descriptor content mismatch')
            if size is not None and (type(size) is not int or size != len(content)):
                raise ValueError('Image descriptor size mismatch')
            return document

        if config_digest != image_id:
            try:
                root = blob(image_id)
                if root.get('mediaType') in (
                        'application/vnd.oci.image.index.v1+json',
                        'application/vnd.docker.distribution.manifest.list.v2+json'):
                    matches = [entry for entry in root.get('manifests', [])
                               if entry.get('platform', {}).get('os') == 'linux'
                               and entry.get('platform', {}).get('architecture') == 'amd64']
                    if len(matches) != 1:
                        raise ValueError('Expected one Linux/amd64 image descriptor')
                    root = blob(matches[0]['digest'], matches[0]['size'])
                if root.get('mediaType') not in (
                        'application/vnd.oci.image.manifest.v1+json',
                        'application/vnd.docker.distribution.manifest.v2+json'):
                    raise ValueError('Unsupported qualified image descriptor')
                if root.get('config', {}).get('digest') != config_digest:
                    raise ValueError('Manifest config differs from saved image')
                blob(config_digest, root['config']['size'])
            except KeyError as error:
                raise ValueError('Archive differs from the qualified image ID') from error
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
        'image_id': image_id,
        'image_config_digest': config_digest,
        'archive': {'name': archive.name, 'sha256': digest, 'size': archive.stat().st_size},
        'qualification': 'Local image checks passed before archive upload; not a registry manifest digest, release, or deployment acceptance.',
    }


def verify(archive, receipt_path, image_id, revision, run_id, attempt, archive_sha256):
    """Bind downloaded bytes to independently supplied workflow identity."""
    receipt_path = Path(receipt_path)
    if receipt_path.stat().st_size > 1024 * 1024:
        raise ValueError('Runtime receipt exceeds size limit')
    receipt = json.loads(receipt_path.read_text())
    expected = record(archive, image_id, revision, run_id, attempt)
    if (not re.fullmatch(r'[0-9a-f]{64}', archive_sha256)
            or expected['archive']['sha256'] != archive_sha256):
        raise ValueError('Archive checksum differs from expected workflow identity')
    if receipt != expected:
        raise ValueError('Retained runtime receipt differs from archive or expected workflow identity')
    return expected


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--archive-sha256')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path)
    mode.add_argument('--verify-receipt', type=Path)
    args = parser.parse_args()
    if args.verify_receipt:
        if args.archive_sha256 is None:
            parser.error('--verify-receipt requires the independently expected --archive-sha256')
        verify(args.archive, args.verify_receipt, args.image_id, args.revision, args.run_id, args.attempt, args.archive_sha256)
        print('Retained runtime matches expected image, source, run and archive digest')
    else:
        receipt = record(args.archive, args.image_id, args.revision, args.run_id, args.attempt)
        args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
