"""The fixed verifier import graph must be present in the container build context."""
from pathlib import Path
import shlex


def test_explicit_admission_copies_are_allowed_into_build_context():
    root=Path(__file__).resolve().parents[1]
    docker=(root/'Dockerfile').read_text()
    rules=(root/'.dockerignore').read_text().splitlines()
    paths={part for line in docker.splitlines() if line.startswith('COPY ') and '--from=' not in line for part in shlex.split(line)[1:-1] if part.startswith('admission/')}
    assert {'admission/contact-document.mjs','admission/contact_source.py'}<=paths
    for path in paths:
        if Path(path).suffix in ('.py','.mjs'):
            assert (root/path).is_file(),path
        assert '!'+path in rules,path
