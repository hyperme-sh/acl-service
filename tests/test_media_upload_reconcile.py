"""Upload intent classification does not mutate or authorize delivery."""
from copy import deepcopy
import pytest
from acl_service.domain.media_upload_reconcile import upload_state
from acl_service.domain.history_store import AdmissionRejected

OWNER='owner'
GRANT={'claims':{'owner':OWNER,'accessor':OWNER,'epoch':1,'grantRevision':1,'stated':1},'proof':{'signature':'signed'}}
SNAPSHOT={'entries':[]}
EPOCH={'document':{'manifest':{'epoch':1,'previousEpoch':0,'revisionId':'b'},'snapshot':SNAPSHOT},
       'finalization':{'epoch':1,'previousEpoch':0,'previousFinalizationId':'','revisionId':'b'}}
WRAP={'reader':OWNER,'record':'a','digest':'a','epoch':1,'revisionId':'b','readerEpub':'key','itemDigest':'c'}


def empty():return {'frozen':[],'manifests':[],'finalizations':[],'wraps':{}}
def state(doc,op,payload,latest=None,snapshot=SNAPSHOT):
    before=deepcopy(doc)
    result=upload_state(doc,latest or {},snapshot,OWNER,op,payload)
    assert doc==before
    return result


def test_grant_absent_exact_applied_changed_and_frozen():
    doc=empty()
    assert state(doc,'grant',GRANT)=='absent'
    assert state(doc,'grant',GRANT,{OWNER:GRANT})=='applied'
    for changed in [{**GRANT,'proof':{}},{**GRANT,'claims':{**GRANT['claims'],'stated':True}},
                    {**GRANT,'claims':{**GRANT['claims'],'until':1}}]:
        assert state(doc,'grant',changed,{OWNER:GRANT})=='conflict'
    doc['frozen']=[OWNER]
    assert state(doc,'grant',GRANT,{OWNER:GRANT})=='conflict'


def test_epoch_exact_pair_snapshot_and_competing_history():
    doc=empty();assert state(doc,'epoch',EPOCH)=='absent'
    doc['manifests']=[{'document':EPOCH['document']}]
    assert state(doc,'epoch',EPOCH)=='conflict'
    doc['finalizations']=[{'proof':EPOCH['finalization']}]
    assert state(doc,'epoch',EPOCH)=='applied'
    assert state(doc,'epoch',EPOCH,snapshot={'entries':[{}]})=='conflict'
    changed=deepcopy(EPOCH);changed['finalization']['signature']='foreign'
    assert state(doc,'epoch',changed)=='conflict'
    changed=deepcopy(EPOCH);changed['document']['manifest']['deviceId']='foreign'
    assert state(doc,'epoch',changed)=='conflict'
    doc['finalizations']*=2
    assert state(doc,'epoch',EPOCH)=='conflict'


def test_wrap_absent_applied_changed_and_frozen():
    doc=empty()
    assert state(doc,'wrap',WRAP)=='conflict'
    doc['manifests']=[{'document':EPOCH['document']}];doc['finalizations']=[{'proof':EPOCH['finalization']}]
    assert state(doc,'wrap',WRAP)=='absent'
    doc['wraps'][OWNER]=WRAP
    assert state(doc,'wrap',WRAP)=='applied'
    assert state(doc,'wrap',{**WRAP,'digest':'other'})=='conflict'
    doc['frozen']=[OWNER]
    assert state(doc,'wrap',WRAP)=='conflict'


@pytest.mark.parametrize('op,payload',[('unknown',{}),('grant',None),('grant',{}),
    ('grant',{**GRANT,'claims':{**GRANT['claims'],'accessor':'foreign'}}),('epoch',{}),
    ('epoch',{**EPOCH,'finalization':{**EPOCH['finalization'],'previousEpoch':1}}),
    ('wrap',{}),('wrap',{**WRAP,'reader':'foreign'})])
def test_only_initial_owner_upload_intents(op,payload):
    with pytest.raises(AdmissionRejected):state(empty(),op,payload)


def test_frozen_epoch_and_superseded_wrap_never_appear_applied():
    doc=empty();doc['manifests']=[{'document':deepcopy(EPOCH['document'])}]
    doc['finalizations']=[{'proof':deepcopy(EPOCH['finalization'])}];doc['wraps'][OWNER]=WRAP
    doc['frozen']=[OWNER]
    assert state(doc,'epoch',EPOCH)=='conflict'
    doc['frozen']=[]
    assert state(doc,'wrap',WRAP,snapshot={'entries':[{}]})=='conflict'
    for side in ['manifests','finalizations']:
        changed=deepcopy(doc);changed[side]*=2
        assert state(changed,'wrap',WRAP)=='conflict'
        changed['wraps']={}
        assert state(changed,'wrap',WRAP)=='conflict'
    for side,key in [('manifests','document'),('finalizations','proof')]:
        for field,value in [('epoch',2),('revisionId','successor')]:
            changed=deepcopy(doc);row=changed[side][0][key]
            if side=='manifests':row=row['manifest']
            row[field]=value
            assert state(changed,'wrap',WRAP)=='conflict'
