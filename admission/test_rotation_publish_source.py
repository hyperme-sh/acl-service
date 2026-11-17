"""Substituted source/native units; no database or configuration activation."""
import copy
import hashlib
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest
from rotation_publish_source import RotationPublishSource
from statement_source import encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict, HistorySnapshot


@pytest.fixture
def setup():
    state=SimpleNamespace(now=100,finish=lambda:None)
    policy={'activePrincipals':['owner'],'trust':{}}
    @contextmanager
    def transaction(**kwargs):
        yield object()
        state.finish();kwargs['before_commit']()
    store=SimpleNamespace(require_authority_checkpoint=True,has_freshness=True,
        _transaction=transaction,_observe_floor=Mock())
    record={'kind':'rotate','principal':'owner','authorizer':{'kind':'wallet'},'attest':'signed'}
    accounts={'owner':HistorySnapshot('owner',b'{}',(encoded(record),))}
    head={'sequence':1,'currentKey':'key','currentEpub':'epub','diagnostics':[]}
    native=Mock();native._run_verifier.side_effect=lambda *a,**kw:json.dumps(head)
    native.admit.side_effect=lambda *a,**kw:kw['before_commit']()
    with patch('rotation_publish_source.HistoryAdmission',return_value=native),\
         patch('rotation_publish_source.StatementSource._accounts',return_value=accounts):
        source=RotationPublishSource(store,policy_at=lambda _:copy.deepcopy(policy),clock=lambda:state.now)
        yield source,state,policy,record,accounts,head,native


def test_append_and_exact_state_share_native_boundary(setup):
    source,state,policy,record,accounts,head,native=setup
    digest=hashlib.sha256(encoded(record)).hexdigest()
    assert source.publish_wallet_rotation('owner',record)=={'recordHash':digest}
    assert native.admit.call_args.args==('owner',encoded(record))
    result=source.wallet_rotation_state('owner',digest)
    assert result=={'recordHash':digest,'present':True,'head':{'sequence':1,'currentKey':'key','currentEpub':'epub'}}
    assert source.wallet_rotation_state('owner','0'*64)['present'] is False
    accounts['owner']=HistorySnapshot('owner',b'{}',(b'{"kind":"wallet"}',))
    assert source.wallet_rotation_state('owner',digest)['present'] is False


@pytest.mark.parametrize('change',['clock','policy','cancel'])
def test_changed_authority_refuses_state_delivery_and_append_commit(setup,change):
    source,state,policy,record,accounts,head,native=setup
    cancel=Mock()
    def alter():
        if change=='clock':state.now+=1
        if change=='policy':policy['activePrincipals']=[]
        if change=='cancel':cancel.side_effect=HistoryConflict('cancelled')
    state.finish=alter
    with pytest.raises(HistoryConflict):source.wallet_rotation_state('owner','0'*64,cancel=cancel)
    state.now=100;policy['activePrincipals']=['owner'];cancel.side_effect=None
    def admission(*a,**kw):alter();kw['before_commit']()
    native.admit.side_effect=admission
    with pytest.raises(HistoryConflict):source.publish_wallet_rotation('owner',record,cancel=cancel)


def test_invalid_owner_record_source_and_hash_refuse(setup):
    source,state,policy,record,accounts,head,native=setup
    for bad in ({},dict(record,principal='other'),dict(record,kind='wallet'),dict(record,authorizer=None),
                dict(record,authorizer={'kind':'oidc-fresh-login'}),dict(record,attest=''),dict(record,attest=1),dict(record,large='x'*65537)):
        with pytest.raises(AdmissionRejected):source.publish_wallet_rotation('owner',bad)
    with pytest.raises(AdmissionRejected):source.publish_wallet_rotation('other',dict(record,principal='other'))
    for bad in ('0'*63,'A'*64,None):
        with pytest.raises(AdmissionRejected):source.wallet_rotation_state('owner',bad)
    source.store.has_freshness=False
    with pytest.raises(ValueError):RotationPublishSource(source.store,policy_at=None)
    native.admit.assert_not_called()


def test_unknown_owner_diagnostics_and_bad_native_head_refuse(setup):
    source,state,policy,record,accounts,head,native=setup
    for update in ({'diagnostics':['invalid']},{'sequence':True},{'sequence':-1},{'extra':1}):
        saved=copy.deepcopy(head);head.update(update)
        with pytest.raises(AdmissionRejected):source.wallet_rotation_state('owner','0'*64)
        head.clear();head.update(saved)
    accounts.clear()
    with pytest.raises(AdmissionRejected):source.wallet_rotation_state('owner','0'*64)
