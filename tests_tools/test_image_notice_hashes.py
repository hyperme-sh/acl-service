import importlib.util
import json
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('image_scan',Path(__file__).resolve().parents[1]/'scripts/classify_base_fingerprint.py')
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)

@pytest.mark.parametrize('change',['none','digest','record','path','line','rule'])
def test_only_reviewed_notice_hash_is_accepted(tmp_path,change):
    supplement={'runtime_sha256':{'auth_service/keycloak_oidc.py':'a'*64},'commit':'reviewed'}
    data=[{'name':'auth-service','supplement':supplement}]
    path=tmp_path/'0/usr/share/acl-service/notices/python/index.json'
    path.parent.mkdir(parents=True)
    text=json.dumps(data,indent=2);path.write_text(text)
    number=next(i for i,line in enumerate(text.splitlines(),1) if 'keycloak_oidc.py' in line)
    finding={'File':str(path),'RuleID':'generic-api-key','StartLine':number,'EndLine':number,'Secret':'a'*64}
    if change=='digest':finding['Secret']='b'*64
    if change=='record':supplement=dict(supplement,commit='changed')
    if change=='path':finding['File']=str(tmp_path/'outside.json')
    if change=='line':finding['StartLine']=finding['EndLine']=1
    if change=='rule':finding['RuleID']='other'
    assert scan.known_notice_hash(finding,tmp_path,supplement)==(change=='none')
