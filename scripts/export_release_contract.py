"""Inspect complete ACL wheel contents without importing candidate code."""
import argparse
import email.parser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile


def snapshot(wheel):
    raw = Path(wheel).read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any('..' in PurePosixPath(n).parts or n.startswith('/') for n in names):
            raise ValueError('Duplicate or unsafe wheel paths')
        metadata_files = [n for n in names if re.fullmatch(r'acl_service-[^/]+\.dist-info/METADATA', n)]
        if len(metadata_files) != 1:
            raise ValueError('Expected one ACL distribution')
        prefix = metadata_files[0].removesuffix('METADATA')
        runtime = [n for n in names if not n.startswith(prefix)]
        if not runtime or any(not n.startswith('acl_service/') for n in runtime):
            raise ValueError('Unexpected distribution contents')
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_files[0]))
        versions = metadata.get_all('Version', [])
        if metadata.get_all('Name') != ['acl-service'] or len(versions) != 1:
            raise ValueError('Wrong or ambiguous distribution identity')
        ver = versions[0]
        if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', ver) or prefix != f'acl_service-{ver}.dist-info/':
            raise ValueError('Invalid package version')
        contents = {n: archive.read(n) for n in sorted(runtime)}
    root = contents.get('acl_service/__init__.py')
    if root is None:
        raise ValueError('Missing ACL package exports')
    contract = {'schema_version': 1,
                'coverage': 'conservative complete packaged ACL runtime and dependency declarations; implementation changes require compatibility assessment',
                'requires_python': metadata.get('Requires-Python'),
                'requires_dist': sorted(metadata.get_all('Requires-Dist', [])),
                'packaged_file_sha256': {n: hashlib.sha256(b).hexdigest() for n, b in contents.items()}}
    encoded = (json.dumps(contract, sort_keys=True, indent=2)+'\n').encode()
    evidence = {'schema_version': 1, 'distribution': 'acl-service', 'version': ver,
                'wheel_sha256': hashlib.sha256(raw).hexdigest(), 'wheel_size': len(raw),
                'contract_sha256': hashlib.sha256(encoded).hexdigest(),
                'qualification': 'artifact inspection; semantic/provider qualification is separate'}
    return encoded, evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    contract, evidence = snapshot(args.wheel)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'contract.json').write_bytes(contract)
    (args.output/'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
