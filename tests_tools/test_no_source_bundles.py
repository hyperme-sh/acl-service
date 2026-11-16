import importlib.util
import io
import json
from pathlib import Path
import tarfile
import pytest

spec=importlib.util.spec_from_file_location('no_sources',Path(__file__).resolve().parents[1]/'scripts/assert_no_source_bundles.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)


def test_runtime_python_and_legal_text_are_not_source_bundles():
    for path in ['opt/venv/lib/python3.13/site-packages/certifi/core.py','usr/share/doc/libc6/copyright','usr/share/acl-service/notices/python/psycopg/LICENSE']:
        assert not audit.prohibited(path)


def test_deleted_lower_layer_bundle_is_rejected(tmp_path):
    image=tmp_path/'image.tar'
    def add(archive,name,data):
        info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
    with tarfile.open(image,'w') as outer:
        add(outer,'manifest.json',json.dumps([{'Layers':['old.tar','new.tar']}]).encode())
        for layer,path in [('old.tar','usr/share/acl-service/sources/dependency.tar.gz'),('new.tar','usr/share/acl-service/.wh.sources')]:
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as inner:add(inner,path,b'fixture')
            add(outer,layer,stream.getvalue())
    with pytest.raises(ValueError,match='Source bundle'):
        audit.verify(image)
