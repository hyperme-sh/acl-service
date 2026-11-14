"""Read-only comparison of retained owner sharing intents."""
from acl_service.domain.media_upload_reconcile import same
from acl_service.domain.history_store import AdmissionRejected


def share_state(doc, latest, snapshot, owner, operation, payload):
    if type(payload) is not dict: raise AdmissionRejected('invalid sharing intent')
    if owner in doc['frozen']: return 'conflict'
    if operation == 'grant':
        claims=payload.get('claims')
        if (set(payload)!={'claims','proof'} or type(claims) is not dict or claims.get('owner')!=owner
                or type(claims.get('accessor')) is not str or type(claims.get('epoch')) is not int or claims['epoch']<2
                or type(claims.get('grantRevision')) is not int or claims['grantRevision']<1 or claims.get('stated')!=1):
            raise AdmissionRejected('sharing grant required')
        who=claims['accessor'];held=latest.get(who)
        if who in doc['frozen']: return 'conflict'
        if held and same(held['claims'],claims) and same(held['proof'],payload['proof']): return 'applied'
        # Only the immediate revision can be missing. A changed or later grant
        # must not be overwritten while resuming an older signed plan.
        revision=held['claims']['grantRevision'] if held else 0
        return 'absent' if claims['grantRevision']==revision+1 and (not held or held['claims']['epoch']<claims['epoch']) else 'conflict'
    if operation == 'epoch':
        document,fin=payload.get('document'),payload.get('finalization')
        if set(payload)!={'document','finalization'} or type(document) is not dict or type(document.get('manifest')) is not dict or type(fin) is not dict:
            raise AdmissionRejected('sharing epoch required')
        manifest=document.get('manifest',{});epoch=manifest.get('epoch');previous=manifest.get('previousEpoch')
        if (type(epoch) is not int or type(previous) is not int or previous<1 or epoch!=previous+1
                or fin.get('epoch')!=epoch or fin.get('previousEpoch')!=previous
                or fin.get('revisionId')!=manifest.get('revisionId')): raise AdmissionRejected('sharing epoch required')
        if not same(document.get('snapshot'),snapshot): return 'conflict'
        manifests=[r['document'] for r in doc['manifests'] if r['document']['manifest']['epoch']>=epoch]
        finals=[r['proof'] for r in doc['finalizations'] if r['proof']['epoch']>=epoch]
        if manifests or finals:
            return 'applied' if len(manifests)==len(finals)==1 and same(manifests[0],document) and same(finals[0],fin) else 'conflict'
        parents=[r['proof'] for r in doc['finalizations'] if r['proof']['epoch']==previous]
        return 'absent' if len(parents)==1 and parents[0]['finalizationId']==fin.get('previousFinalizationId') else 'conflict'
    if operation == 'wrap':
        if (set(payload)!={'reader','record','digest','epoch','revisionId','readerEpub','itemDigest'}
                or type(payload.get('reader')) is not str or type(payload.get('epoch')) is not int or payload['epoch']<2): raise AdmissionRejected('sharing wrap required')
        who=payload['reader'];grant=latest.get(who)
        if who in doc['frozen'] or not grant or grant['claims']['stated']!=1 or grant['claims']['epoch']!=payload['epoch']: return 'conflict'
        manifests=[r['document'] for r in doc['manifests'] if r['document']['manifest']['epoch']>=payload['epoch']]
        finals=[r['proof'] for r in doc['finalizations'] if r['proof']['epoch']>=payload['epoch']]
        if (len(manifests)!=1 or len(finals)!=1 or manifests[0]['manifest']['revisionId']!=payload['revisionId']
                or finals[0]['revisionId']!=payload['revisionId'] or not same(manifests[0]['snapshot'],snapshot)): return 'conflict'
        held=doc['wraps'].get(who)
        if held and same(held,payload): return 'applied'
        return 'absent' if not held or held['epoch']<payload['epoch'] else 'conflict'
    raise AdmissionRejected('invalid sharing operation')
