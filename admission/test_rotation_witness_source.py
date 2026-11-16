"""Substituted transaction/native/signer units; no policy or database activation."""
import copy
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest
from rotation_witness_source import RotationWitnessSource
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict, HistorySnapshot


@pytest.fixture
def source():
    state=SimpleNamespace(now=100,committed=False,leased=False,finish=lambda:None)
    policy={'activePrincipals':['owner'],'trust':{'jwks':{'keys':[{
        'kid':'key','notBefore':0,'notAfter':1000,'x':'AA','y':'AA'}]}}}
    @contextmanager
    def lease():
        state.leased=True
        try:yield SimpleNamespace(jwks=copy.deepcopy(policy['trust']['jwks']))
        finally:state.leased=False
    @contextmanager
    def transaction(**kwargs):
        assert state.leased
        yield object()
        state.finish()
        kwargs['before_commit']()
        state.committed=True
    store=SimpleNamespace(require_authority_checkpoint=True,has_freshness=True,
        _transaction=transaction,_observe_floor=Mock())
    accounts={'owner':HistorySnapshot('owner',b'{}',())}
    result={'issuedAt':90,'heads':{'owner':0},'claims':{'typ':'sociacl-rotate-attest-v4','principal':'owner'}}
    signer=Mock();signer.sign_verified.return_value='signed-token'
    with patch('rotation_witness_source.StatementSource._accounts',return_value=accounts),\
         patch('rotation_witness_source.HistoryAdmission._run_verifier',side_effect=lambda *a,**k:json.dumps(result)),\
         patch('rotation_witness_source.ec.EllipticCurvePublicNumbers'),\
         patch('rotation_witness_source.WitnessKey',return_value=SimpleNamespace(not_after=1000)),\
         patch('rotation_witness_source.WitnessSigner',return_value=signer):
        value=RotationWitnessSource(store,policy_at=lambda _:copy.deepcopy(policy),
            witness_policy=SimpleNamespace(locked_policy=lease),kid='key',private_key=object(),clock=lambda:state.now)
        yield value,state,policy,result,signer


def test_signing_holds_policy_lease_through_commit(source):
    value,state,policy,result,signer=source
    assert value.attest_wallet_rotation('owner',{'issuedAt':90})=='signed-token'
    assert state.committed and not state.leased
    signer.sign_verified.assert_called_once_with(result['claims'],issued_at=90,lifetime=900)
    value.store._observe_floor.assert_called_once()


@pytest.mark.parametrize('change',['clock','policy','cancel'])
def test_final_guard_prevents_token_delivery(source,change):
    value,state,policy,result,signer=source
    cancel=Mock()
    def finish():
        if change=='clock':state.now=101
        if change=='policy':policy['activePrincipals']=[]
        if change=='cancel':cancel.side_effect=HistoryConflict('cancelled')
    state.finish=finish
    with pytest.raises(HistoryConflict):value.attest_wallet_rotation('owner',{'issuedAt':90},cancel=cancel)
    assert not state.committed


def test_invalid_source_owner_capacity_and_native_heads_refuse(source):
    value,state,policy,result,signer=source
    with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('other',{})
    with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('owner',{'large':'x'*65537})
    for heads in ({},{'owner':True},{'owner':-1}):
        result['heads']=heads
        with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('owner',{'issuedAt':90})
    assert not signer.sign_verified.called
    value.store.has_freshness=False
    with pytest.raises(ValueError):RotationWitnessSource(value.store,policy_at=None,witness_policy=None,kid='',private_key=None)


def test_missing_policy_key_or_owner_refuse(source):
    value,state,policy,result,signer=source
    value.kid='missing'
    with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('owner',{'issuedAt':90})
    value.kid='key'
    with patch('rotation_witness_source.StatementSource._accounts',return_value={}):
        with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('owner',{'issuedAt':90})
    @contextmanager
    def missing():yield None
    value.witness_policy.locked_policy=missing
    with pytest.raises(AdmissionRejected):value.attest_wallet_rotation('owner',{'issuedAt':90})


def test_native_refusal_signing_failure_and_lease_exit_failure_propagate(source):
    value,state,policy,result,signer=source
    signer.sign_verified.side_effect=ValueError('signer refused')
    with pytest.raises(ValueError):value.attest_wallet_rotation('owner',{'issuedAt':90})
    assert not state.committed
    signer.sign_verified.side_effect=None
    @contextmanager
    def changed():
        yield SimpleNamespace(jwks=policy['trust']['jwks'])
        raise HistoryConflict('lease ended')
    value.witness_policy.locked_policy=changed
    with pytest.raises(HistoryConflict):value.attest_wallet_rotation('owner',{'issuedAt':90})


@pytest.mark.parametrize('field,value',[('issuedAt',91),('principal','foreign'),('typ','other')])
def test_native_output_is_bound_to_requested_owner_and_time(source,field,value):
    instance,state,policy,result,signer=source
    if field=='issuedAt':result[field]=value
    else:result['claims'][field]=value
    with pytest.raises(AdmissionRejected):
        instance.attest_wallet_rotation('owner',{'issuedAt':90})
    assert not signer.sign_verified.called and not state.committed
