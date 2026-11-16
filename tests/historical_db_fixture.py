"""Load only archived DB schema files into disposable CI test processes."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import zipfile

import controlplane_db


def install():
    if hasattr(controlplane_db, '_acl_schema_fixture'):
        return
    directory = Path(__file__).resolve().parents[1] / 'tests_artifacts/dependencies'
    records = json.loads((directory / 'manifest.json').read_text())['dependencies']
    record, = [row for row in records if row['distribution'] == 'controlplane-db']
    filename = record['wheel']
    if Path(filename).name != filename:
        raise ValueError('Invalid schema fixture filename')
    archive = directory / filename
    if hashlib.sha256(archive.read_bytes()).hexdigest() != record['sha256']:
        raise ValueError('Schema fixture digest mismatch')
    scratch = tempfile.TemporaryDirectory(prefix='acl-test-schema-')
    with zipfile.ZipFile(archive) as wheel:
        for name in wheel.namelist():
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe schema fixture path')
            if name == 'controlplane_db/migrations.py' or name.startswith((
                'controlplane_db/migration_chains/', 'controlplane_db/alembic/'
            )):
                wheel.extract(name, scratch.name)
    # Keep the directory alive for subsequent schema imports in the same process.
    controlplane_db._acl_schema_fixture = scratch
    controlplane_db.__path__.append(str(Path(scratch.name) / 'controlplane_db'))


install()
