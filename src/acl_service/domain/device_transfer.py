"""Bounded public transfer authority request shapes. Times use SDK milliseconds."""
import re
from urllib.parse import urlsplit
from acl_service.infrastructure.contact_journal import PRINCIPAL


def principal_value(value):
    if type(value) is not str or PRINCIPAL.fullmatch(value) is None: raise ValueError('invalid principal')
    return value


def scope_value(scope):
    if type(scope) is not dict or set(scope) != {'sourceOrigin','destinationOrigin','application','tenant','audience'}:
        raise ValueError('invalid scope')
    for value in scope.values():
        if type(value) is not str or not 1 <= len(value) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError('invalid scope')
    for name in ('sourceOrigin','destinationOrigin'):
        value = scope[name]
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or parsed.netloc != parsed.netloc.lower():
            raise ValueError('invalid origin')
    return scope


def identity_value(identity):
    if type(identity) is not dict or set(identity) != {'principal','pub','epub','rotationSeq'}: raise ValueError('invalid identity')
    for key in ('principal','pub','epub'): principal_value(identity[key])
    if type(identity['rotationSeq']) is not int or not 0 <= identity['rotationSeq'] <= 1024: raise ValueError('invalid sequence')
    return identity


def request_value(action, body):
    if type(body) is not dict: raise ValueError('invalid request')
    if action == 'state':
        if set(body) != {'scope','identity'}: raise ValueError('invalid request')
        return scope_value(body['scope']), identity_value(body['identity']), None, None
    if action != 'current' or set(body) not in ({'binding'}, {'binding','expectedRevision'}): raise ValueError('invalid request')
    b = body['binding']
    if type(b) is not dict or set(b) != {'session','transcript','expiresAt','scope','identity'}: raise ValueError('invalid binding')
    for name in ('session','transcript'):
        if type(b[name]) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}', b[name]): raise ValueError('invalid binding')
    if type(b['expiresAt']) is not int or not 0 < b['expiresAt'] <= 9007199254740991: raise ValueError('invalid expiry')
    revision = body.get('expectedRevision')
    if 'expectedRevision' in body and (type(revision) is not str or not re.fullmatch('[a-f0-9]{64}', revision)): raise ValueError('invalid checkpoint')
    return scope_value(b['scope']), identity_value(b['identity']), b, revision
