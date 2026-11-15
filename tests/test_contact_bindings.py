import json
from io import BytesIO
from unittest.mock import patch

import pytest

from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.contact_bindings import parse_settings, read_trust, load_contact_bindings

OWNER='a'*43+'.'+'b'*43


def binding():return {'tenant':'12345678-1234-1234-1234-123456789abc','subject':'reader','principal':OWNER,'postgresFile':'/private/postgres.json','policyFile':'/private/policy.json'}
def document(rows=None):return json.dumps({'version':1,'bindings':rows if rows is not None else [binding()]}).encode()


def test_configuration_is_explicit_and_subject_unique():
    assert load_contact_bindings({}) is None
    assert parse_settings(document())[0].principal==OWNER
    for rows in ([],[binding(),binding()]):
        with pytest.raises(ValueError):parse_settings(document(rows))


@pytest.mark.parametrize('patch', [{'tenant':'bad'},{'subject':'bad subject'},{'principal':'bad'},
    {'postgresFile':'relative'},{'policyFile':'/private/../other'},{'extra':1}])
def test_malformed_binding_refuses(patch):
    with pytest.raises((ValueError,TypeError)):parse_settings(document([{**binding(),**patch}]))


def test_trust_expires_and_callers_cannot_mutate_held_policy():
    raw=json.dumps({'version':1,'from':100,'until':200,'trust':{'jwks':{'keys':[]},'policy':{},'pinnedIss':[]}}).encode()
    with patch('acl_service.infrastructure.contact_bindings._private_file',return_value=BytesIO(raw)):
        trust=read_trust('/fixture/policy.json')
    first=trust(100);first['jwks']['keys'].append('untrusted')
    assert trust(199)['jwks']['keys']==[]
    for at in (99,200,True):
        with pytest.raises(AdmissionRejected):trust(at)


def test_invalid_private_config_error_contains_no_values():
    with pytest.raises(ValueError,match='^Invalid contact source configuration$'):
        load_contact_bindings({'SOCIACL_CONTACT_BINDINGS_FILE':'/does/not/exist'})
