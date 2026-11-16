"""Reject hosted billing/provider payloads in every newly built image layer."""
import json
from pathlib import PurePosixPath
import sys
import tarfile

from container_audit import check_member


def verify(archive):
    with tarfile.open(archive) as image:
        manifest = json.load(image.extractfile('manifest.json'))
        if len(manifest) != 1:
            raise ValueError('Expected one qualified image')
        for filename in manifest[0]['Layers']:
            with tarfile.open(fileobj=image.extractfile(filename)) as layer:
                for member in layer:
                    parts = PurePosixPath(member.name).parts
                    if 'site-packages' not in parts:
                        continue
                    name = '/'.join(parts[parts.index('site-packages') + 1:])
                    data = layer.extractfile(member).read() if member.isfile() else b''
                    check_member(name, data)
    return len(manifest[0]['Layers'])


if __name__ == '__main__':
    print('No hosted dependencies in any of %d image layers' % verify(sys.argv[1]))
