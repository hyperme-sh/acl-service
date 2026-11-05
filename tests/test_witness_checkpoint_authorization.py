import base64
import hashlib
import json
from dataclasses import replace

import pytest

from acl_service.infrastructure.witness_checkpoint_authorization import RefreshEnrollment
from acl_service.infrastructure.witness_signer import WitnessRejected
from acl_service.infrastructure import witness_checkpoint_continuity as source
from test_witness_checkpoint_continuity import pinned  # noqa: F401
from test_witness_checkpoint import ready, engine, state_engine, state_url, FIXTURE, verify_response  # noqa: F401

NOW = FIXTURE['now']
TOKEN = bytes(range(32))
HEADER = 'Bearer ' + base64.urlsafe_b64encode(TOKEN).rstrip(b'=').decode()
ENROLLMENT = RefreshEnrollment('client-enrollment-1', FIXTURE['state']['audience'], 1,
                               hashlib.sha256(TOKEN).digest(), NOW, NOW + 10)
REQUEST = dict(type='sociacl-witness-checkpoint-request-v1', operation='refresh',
               client=ENROLLMENT.client, audience=ENROLLMENT.audience, rootEpoch=1,
               challenge=base64.urlsafe_b64encode(b'c'*32).rstrip(b'=').decode())
BODY = json.dumps(REQUEST).encode()


def test_exact_scope_authorized():
    assert ENROLLMENT.authorize(BODY, HEADER, NOW) == REQUEST['challenge']


@pytest.mark.parametrize('key,value', [('type','other'),('operation','enroll'),('operation','recover'),
    ('operation','migrate'),('client','other'),('audience','other'),('rootEpoch',2),
    ('rootEpoch',True),('challenge','x'),('challenge','A'*42+'B'),('extra',1)])
def test_scope_and_schema_refused(key, value):
    request = dict(REQUEST); request[key] = value
    with pytest.raises(WitnessRejected): ENROLLMENT.authorize(json.dumps(request).encode(), HEADER, NOW)


@pytest.mark.parametrize('header', ['', 'Bearer '+ 'A'*43, HEADER+'=', HEADER+'\n', 'Basic '+HEADER[7:],
    'bearer '+HEADER[7:], 'Bearer '+'a'*8193, None])
def test_invalid_credentials(header):
    with pytest.raises(WitnessRejected): ENROLLMENT.authorize(BODY, header, NOW)


@pytest.mark.parametrize('body', [b'[]', b'null', b'{', b'\xff', b'{"type":1,"type":2}', b'x'*8193])
def test_invalid_body(body):
    with pytest.raises(WitnessRejected): ENROLLMENT.authorize(body, HEADER, NOW)


@pytest.mark.parametrize('changes', [dict(client=''), dict(audience='\ud800'),dict(root_epoch=True),
    dict(credential_sha256=b'x'),dict(not_before=NOW+1),dict(expires_at=NOW),dict(expires_at=True)])
def test_invalid_or_expired_enrollment(changes):
    with pytest.raises(WitnessRejected): replace(ENROLLMENT, **changes).authorize(BODY, HEADER, NOW)


def sign(ready, config, **extra):
    return ENROLLMENT.sign_refresh(BODY, HEADER, config, ready['engine'], ready['policy_payload'],
        ready['policy_signature'], ready['policy_root'], management_private_key=ready['management_private_key'], **extra)


def test_authenticated_issuance_caps_lease(pinned, ready):
    _, config, _ = pinned
    payload = verify_response(sign(ready, config, clock=lambda:NOW))
    assert payload['client'] == ENROLLMENT.client
    assert payload['challenge'] == REQUEST['challenge']
    assert payload['expiresAt'] == ENROLLMENT.expires_at


def test_wrong_credential_before_any_source_access():
    with pytest.raises(WitnessRejected):
        ENROLLMENT.sign_refresh(BODY, 'Bearer '+'A'*43, object(), object(), b'', b'', object(),
            management_private_key=object(), clock=lambda:NOW)


def test_wrong_source_epoch_before_file_access(pinned, ready):
    _, config, _ = pinned
    config.document_file.unlink()
    with pytest.raises(WitnessRejected): sign(ready, replace(config, root_epoch=2), clock=lambda:NOW)


@pytest.mark.parametrize('kind', ['utc', 'monotonic'])
def test_credential_expiry_in_final_read(pinned, ready, monkeypatch, kind):
    _, config, _ = pinned
    now, elapsed, calls = [NOW], [0], [0]
    original = source.read_regular_file
    def read(*args):
        raw = original(*args); calls[0] += 1
        if calls[0] == 2:
            if kind == 'utc': now[0] += 10
            else: elapsed[0] += 10
        return raw
    monkeypatch.setattr(source, 'read_regular_file', read)
    with pytest.raises(WitnessRejected):
        sign(ready, config, clock=lambda:now[0], monotonic=lambda:elapsed[0])
