import importlib.util
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('runtime_legal',Path(__file__).resolve().parents[1]/'scripts/review_runtime_legal.py')
legal=importlib.util.module_from_spec(spec);spec.loader.exec_module(legal)


def test_debian_metadata_preserves_source_version_and_copyright(tmp_path):
    path=tmp_path/'usr/share/doc/libc6/copyright';path.parent.mkdir(parents=True);path.write_text('terms')
    row,=legal.debian_inventory(tmp_path,'libc6:amd64\t2.36-9+deb12u1\tglibc\t2.36-9+deb12u1\n')
    assert row['source']=='glibc'
    assert row['copyright_sha256']==legal.sha(path)
    assert row['upstream_reference'].endswith('/glibc/2.36-9%2Bdeb12u1/')


@pytest.mark.parametrize('kind',['missing','escape'])
def test_missing_or_external_copyright_is_refused(tmp_path,kind):
    if kind=='escape':
        path=tmp_path/'usr/share/doc/libc6/copyright';path.parent.mkdir(parents=True);path.symlink_to('/etc/passwd')
    with pytest.raises(ValueError,match='copyright'):
        legal.debian_inventory(tmp_path,'libc6\t1\tglibc\t1\n')


def test_license_candidates_are_metadata_based_not_clearance():
    rows=[{'name':'example','version':'1','license_expression':'MPL-2.0','texts':{}},
          {'name':'other','version':'1','license_classifiers':['License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'],'texts':{}},
          {'name':'permissive','version':'1','license_expression':'MIT','texts':{}}]
    assert [r['name'] for r in legal.python_candidates(rows)]==['example','other']
