"""Read-only comparison of first-upload intents with protected media state."""
import json
from acl_service.domain.history_store import AdmissionRejected


def same(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def upload_state(doc, latest, snapshot, owner, operation, payload):
    if type(payload) is not dict:
        raise AdmissionRejected('invalid upload intent')
    if operation == 'grant':
        claims = payload.get('claims')
        if (set(payload) != {'claims', 'proof'} or type(claims) is not dict
                or claims.get('owner') != owner or claims.get('accessor') != owner
                or claims.get('epoch') != 1 or claims.get('grantRevision') != 1 or claims.get('stated') != 1):
            raise AdmissionRejected('initial owner grant required')
        held = latest.get(owner)
        if owner in doc['frozen']: return 'conflict'
        if held is None: return 'absent'
        return 'applied' if same(held['claims'], claims) and same(held['proof'], payload['proof']) else 'conflict'
    if operation == 'epoch':
        document, finalization = payload.get('document'), payload.get('finalization')
        if (set(payload) != {'document', 'finalization'} or type(document) is not dict
                or type(document.get('manifest')) is not dict or type(finalization) is not dict
                or document['manifest'].get('epoch') != 1 or document['manifest'].get('previousEpoch') != 0
                or finalization.get('epoch') != 1 or finalization.get('previousEpoch') != 0
                or finalization.get('previousFinalizationId') != ''):
            raise AdmissionRejected('initial epoch required')
        if owner in doc['frozen'] or not same(document.get('snapshot'), snapshot): return 'conflict'
        manifests, finalizations = doc['manifests'], doc['finalizations']
        if not manifests and not finalizations: return 'absent'
        return 'applied' if (len(manifests) == len(finalizations) == 1
            and same(manifests[0]['document'], document) and same(finalizations[0]['proof'], finalization)) else 'conflict'
    if operation == 'wrap':
        if (set(payload) != {'reader', 'record', 'digest', 'epoch', 'revisionId', 'readerEpub', 'itemDigest'}
                or payload['reader'] != owner or payload['epoch'] != 1):
            raise AdmissionRejected('initial owner wrap required')
        if owner in doc['frozen']: return 'conflict'
        manifests, finalizations = doc['manifests'], doc['finalizations']
        if len(manifests) != 1 or len(finalizations) != 1: return 'conflict'
        document, finalization = manifests[0]['document'], finalizations[0]['proof']
        if (document['manifest'].get('epoch') != 1 or document['manifest'].get('revisionId') != payload['revisionId']
                or finalization.get('epoch') != 1 or finalization.get('revisionId') != payload['revisionId']
                or not same(document.get('snapshot'), snapshot)):
            return 'conflict'
        held = doc['wraps'].get(owner)
        if held is None: return 'absent'
        return 'applied' if same(held, payload) else 'conflict'
    raise AdmissionRejected('invalid upload operation')
