from copy import deepcopy
import pytest
from acl_service.domain.media_share_reconcile import share_state
from acl_service.domain.history_store import AdmissionRejected

G={'claims':{'owner':'owner','accessor':'reader','epoch':2,'grantRevision':2,'stated':1},'proof':{'signature':'signed'}}
S={'entries':[]}
E={'document':{'manifest':{'epoch':2,'previousEpoch':1,'revisionId':'b'},'snapshot':S},
   'finalization':{'epoch':2,'previousEpoch':1,'previousFinalizationId':'parent','revisionId':'b','finalizationId':'new'}}
W={'reader':'reader','record':'a','digest':'a','epoch':2,'revisionId':'b','readerEpub':'key','itemDigest':'c'}
def doc():return {'frozen':[],'manifests':[],'finalizations':[{'proof':{'epoch':1,'finalizationId':'parent'}}],'wraps':{}}
def check(d,op,p,latest=None,snapshot=S):
    before=deepcopy(d);result=share_state(d,latest or {},snapshot,'owner',op,p);assert d==before;return result

def test_grants_exact_missing_conflicting_and_frozen():
    d=doc();old=deepcopy(G);old['claims'].update(epoch=1,grantRevision=1)
    assert check(d,'grant',G,{'reader':old})=='absent'
    assert check(d,'grant',G,{'reader':G})=='applied'
    assert check(d,'grant',G)=='conflict'
    first=deepcopy(G);first['claims']['grantRevision']=1
    assert check(d,'grant',first)=='absent'
    changed=deepcopy(G);changed['proof']['signature']='different'
    assert check(d,'grant',changed,{'reader':G})=='conflict'
    old['claims']['epoch']=2;assert check(d,'grant',G,{'reader':old})=='conflict'
    for who in ('owner','reader'):
        d['frozen']=[who];assert check(d,'grant',G)=='conflict'

def test_epochs_reconcile_exact_parent_snapshot_and_competitors():
    d=doc();assert check(d,'epoch',E)=='absent'
    d['finalizations'][0]['proof']['finalizationId']='other';assert check(d,'epoch',E)=='conflict'
    d=doc();d['manifests']=[{'document':E['document']}];assert check(d,'epoch',E)=='conflict'
    d['finalizations'].append({'proof':E['finalization']});assert check(d,'epoch',E)=='applied'
    assert check(d,'epoch',E,snapshot={'entries':[{}]})=='conflict'
    d['manifests']*=2;assert check(d,'epoch',E)=='conflict'
    d=doc();d['finalizations']=[];assert check(d,'epoch',E)=='conflict'

def test_wraps_do_not_replace_same_or_later_epoch():
    d=doc();assert check(d,'wrap',W)=='conflict'
    latest={'reader':G};assert check(d,'wrap',W,latest)=='conflict'
    d['manifests']=[{'document':E['document']}];d['finalizations'].append({'proof':E['finalization']})
    assert check(d,'wrap',W,latest)=='absent'
    d['wraps']['reader']={**W,'epoch':1};assert check(d,'wrap',W,latest)=='absent'
    d['wraps']['reader']=W;assert check(d,'wrap',W,latest)=='applied'
    assert check(d,'wrap',{**W,'digest':'changed'},latest)=='conflict'
    assert check(d,'wrap',W,latest,snapshot={'entries':[{}]})=='conflict'
    d['frozen']=['reader'];assert check(d,'wrap',W,latest)=='conflict'

@pytest.mark.parametrize('op,payload',[
    ('grant',None),('unknown',{}),('grant',{}),('grant',{**G,'claims':[]}),
    ('grant',{**G,'claims':{**G['claims'],'epoch':1}}),('grant',{**G,'claims':{**G['claims'],'accessor':[]}}),
    ('epoch',{}),('epoch',{**E,'document':{'manifest':[]}}),
    ('epoch',{**E,'document':{'manifest':{'epoch':2,'previousEpoch':0}}}),
    ('epoch',{**E,'finalization':{**E['finalization'],'epoch':3}}),
    ('wrap',{}),('wrap',{**W,'reader':[]}),('wrap',{**W,'epoch':1}),
])
def test_malformed_refuses(op,payload):
    with pytest.raises(AdmissionRejected):check(doc(),op,payload)
