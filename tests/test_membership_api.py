"""Decision logic uses injected membership/policy APIs, never database engines."""
from types import SimpleNamespace
from uuid import uuid4
import pytest
from spanopticon_models.sociacl import SociACLRequestContext, SociACLShareMode
from acl_service.domain.sociacl_evaluator import evaluate_share_access
from test_policy_store import MemoryPolicyStore

MODE = next(m.value for m in SociACLShareMode if m.value not in ('notify_only', 'negotiate'))


def share(predicate=None):
    return SimpleNamespace(revoked_at=None, expires_at=None, uses_remaining=None,
                           predicate_json=predicate or {}, mode=MODE)


class Memberships:
    def __init__(self, entries=()):
        self.entries = set(entries)
        self.calls = []

    def user_in_group(self, tenant, subject, group):
        self.calls.append((tenant, subject, group))
        return (tenant, subject, group) in self.entries


def test_verified_subject_and_current_membership_control_decision():
    tenant, group = uuid4(), uuid4()
    entry = (tenant, 'verified', group)
    reader = Memberships([entry])
    link = share({'member_of_group_id': str(group)})
    context = SociACLRequestContext(sub='spoofed')
    def evaluate(subject):
        return evaluate_share_access(reader, tenant, link, context, authenticated_sub=subject)
    assert evaluate(None).decision.value == 'deny'
    assert reader.calls == []
    assert evaluate('spoofed').decision.value == 'deny'
    assert evaluate('verified').decision.value == 'allow'
    reader.entries.remove(entry)
    assert evaluate('verified').decision.value == 'deny'
    assert reader.calls[-1] == entry


@pytest.mark.parametrize('subject', [None, '', 'verified'])
@pytest.mark.parametrize('configured', [False, True])
def test_required_gate_needs_subject_store_and_existing_grant(subject, configured):
    tenant = uuid4()
    store = MemoryPolicyStore() if configured else None
    if store is not None:
        store.add_rule(tenant, 'p', ['verified', 'sociacl:share', 'evaluate'])
    result = evaluate_share_access(Memberships(), tenant, share(), SociACLRequestContext(),
        require_casbin_sociacl_gate=True, casbin_sub=subject, policy_store=store)
    assert result.decision.value == ('allow' if configured and subject == 'verified' else 'deny')


def test_gate_reads_current_tenant_scoped_policy():
    tenant, foreign = uuid4(), uuid4()
    store = MemoryPolicyStore()
    rule = ['verified', 'sociacl:share', 'evaluate']
    store.add_rule(foreign, 'p', rule)
    def evaluate():
        return evaluate_share_access(Memberships(), tenant, share(), SociACLRequestContext(),
            require_casbin_sociacl_gate=True, casbin_sub='verified', policy_store=store)
    assert evaluate().reason_code == 'casbin_denied'
    store.add_rule(tenant, 'p', rule)
    assert evaluate().decision.value == 'allow'
    store.delete_rule(tenant, 'p', rule)
    assert evaluate().reason_code == 'casbin_denied'


def test_membership_failure_cannot_become_allow():
    class Broken:
        def user_in_group(self, *args):
            raise RuntimeError('membership unavailable')
    with pytest.raises(RuntimeError, match='membership unavailable'):
        evaluate_share_access(Broken(), uuid4(), share({'member_of_group_id': str(uuid4())}),
            SociACLRequestContext(), authenticated_sub='verified')


def test_unconfigured_membership_reader_denies_group_access():
    result = evaluate_share_access(None, uuid4(), share({'member_of_group_id': str(uuid4())}),
        SociACLRequestContext(), authenticated_sub='verified')
    assert result.decision.value == 'deny'
