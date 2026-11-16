"""Reject source-distribution bundles in every layer, including deleted files."""
import json
from pathlib import PurePosixPath
import sys
import tarfile


def prohibited(name):
    path=PurePosixPath(name)
    parts=path.parts
    roots=(('usr','share','doc'),('usr','share','acl-service'))
    bundles={'sources','debian-sources','base-sources','source-bundles','source-archives'}
    return (parts[:2]==('usr','src') or
            (any(parts[:len(root)]==root for root in roots) and bool(set(parts)&bundles)) or
            path.name.endswith('.dsc') or '.orig.tar.' in path.name or '.debian.tar.' in path.name)


def verify(archive):
    with tarfile.open(archive) as image:
        manifest=json.load(image.extractfile('manifest.json'))
        if len(manifest)!=1:
            raise ValueError('Expected one qualified image')
        for name in manifest[0]['Layers']:
            with tarfile.open(fileobj=image.extractfile(name)) as layer:
                for member in layer:
                    if not member.isdir() and prohibited(member.name):
                        raise ValueError('Source bundle in image layer: '+member.name)
    return len(manifest[0]['Layers'])


if __name__=='__main__':
    print('No source bundles in any of %d image layers' % verify(sys.argv[1]))
