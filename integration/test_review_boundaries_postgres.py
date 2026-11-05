"""Native PostgreSQL subset adopted from Panopticon #691; HTTP auth remains separate."""

from datetime import datetime, timezone
from types import SimpleNamespace
import uuid

import casbin
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session

from acl_service.infrastructure.membership_reader import PostgresMembershipReader
from acl_service.infrastructure import policy_repo, share_repo
from acl_service.infrastructure.casbin_adapter import TenantCasbinAdapter
from acl_service.infrastructure.enforcer_factory import _RESOURCES, make_enforcer
from acl_service.infrastructure.policy_repo import PostgresPolicyStore
from controlplane_db.models import Group, Role, Tenant, User, UserGroupMembership


@pytest.fixture(scope="module")
def restricted_engine(migrated_sync_url):
    owner = create_engine(migrated_sync_url)
    with owner.begin() as cx:
        cx.execute(text("CREATE ROLE acl_review_tester NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT"))
        cx.execute(text("GRANT acl_review_tester TO CURRENT_USER"))
        cx.execute(text("GRANT USAGE ON SCHEMA public TO acl_review_tester"))
        cx.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON acl_casbin_rules, sociacl_share_links TO acl_review_tester"))
        cx.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO acl_review_tester"))
        cx.execute(text("GRANT SELECT ON users, groups, user_group_memberships TO acl_review_tester"))
    engine = create_engine(migrated_sync_url)

    @event.listens_for(engine, "connect")
    def set_role(connection, _):
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE acl_review_tester")
        connection.commit()

    with engine.connect() as cx:
        assert cx.scalar(text("SELECT current_user")) == "acl_review_tester"
        assert cx.scalar(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")) is False
    try:
        yield engine
    finally:
        engine.dispose()
        with owner.begin() as cx:
            cx.execute(text("DROP OWNED BY acl_review_tester"))
            cx.execute(text("DROP ROLE acl_review_tester"))
        owner.dispose()


@pytest.fixture
def membership(migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    with Session(engine, expire_on_commit=False) as session:
        tenant = Tenant(name="acl-subject-" + uuid.uuid4().hex)
        foreign = Tenant(name="acl-foreign-" + uuid.uuid4().hex)
        session.add_all([tenant, foreign])
        session.flush()
        role = Role(tenant_id=tenant.id, name="member", permissions=[])
        session.add(role)
        session.flush()
        group = Group(tenant_id=tenant.id, name="lab-owners", role_id=role.id)
        user = User(tenant_id=tenant.id, keycloak_sub="issuer|" + uuid.uuid4().hex,
                    email=uuid.uuid4().hex + "@example.com", first_name="Lab", last_name="Owner",
                    gender="prefer_not_to_say", is_active=True)
        session.add_all([group, user])
        session.flush()
        member = UserGroupMembership(tenant_id=tenant.id, user_id=user.id, group_id=group.id)
        session.add(member)
        session.commit()
        data = SimpleNamespace(tenant=tenant.id, foreign=foreign.id, group=group.id,
                               user=user.id, subject=user.keycloak_sub, member=member.id)
    try:
        yield data
    finally:
        with engine.begin() as cx:
            cx.execute(text("DELETE FROM user_group_memberships WHERE id=:id"), {"id": data.member})
            cx.execute(text("DELETE FROM groups WHERE id=:id"), {"id": data.group})
            cx.execute(text("DELETE FROM tenants WHERE id IN (:ta,:tb)"), {"ta": data.tenant, "tb": data.foreign})
        engine.dispose()


def test_post_commit_refresh_restores_rls_and_keeps_foreign_rows_hidden(restricted_engine, seed):
    rule = ["subject-" + uuid.uuid4().hex, "model", "invoke"]
    row = policy_repo.add_rule(restricted_engine, seed.ta, "p", rule)
    assert row.tenant_id == seed.ta and row.v0 == rule[0]
    # Existing-row path must keep its tenant context too.
    assert policy_repo.add_rule(restricted_engine, seed.ta, "p", rule).id == row.id
    link, token = share_repo.create_share(
        restricted_engine, tenant_id=seed.ta, resource_kind="user", resource_descriptor={},
        predicate_json={}, mode="release_if_match", expires_at=None, uses_remaining=3,
        owner_user_id=None, group_id=None, created_by="verified-subject",
    )
    assert link.tenant_id == seed.ta and link.uses_remaining == 3 and token
    with restricted_engine.connect() as cx:
        # There is no session-wide tenant GUC left behind by either refresh.
        assert cx.scalar(text("SELECT current_setting('app.current_tenant_id', true)")) in (None, "")
        cx.execute(text("SELECT set_config('app.current_tenant_id', :tid, true)"), {"tid": str(seed.tb)})
        assert cx.scalar(text("SELECT count(*) FROM sociacl_share_links WHERE id=:id"), {"id": link.id}) == 0
        assert cx.scalar(text("SELECT count(*) FROM acl_casbin_rules WHERE id=:id"), {"id": row.id}) == 0


@pytest.mark.parametrize("filename,extra", [("model_rbac.conf", None), ("model_abac.conf", "budget")])
@pytest.mark.parametrize("filtered", [False, True])
def test_mixed_model_loaders_under_rls(restricted_engine, seed, filename, extra, filtered):
    subject = "model-subject-" + uuid.uuid4().hex
    policy_repo.add_rule(restricted_engine, seed.ta, "p", [subject, "ai", "invoke"])
    policy_repo.add_rule(restricted_engine, seed.ta, "p", [subject, "ai", "invoke", "budget"])
    policy_repo.add_rule(restricted_engine, seed.tb, "p", ["foreign", "ai", "invoke"] + (["budget"] if extra else []))
    if filtered:
        model = casbin.Model()
        model.load_model(str(_RESOURCES / filename))
        adapter = TenantCasbinAdapter(restricted_engine, seed.ta)
        adapter.load_filtered_policy(model, SimpleNamespace(ptype=[], v0=[], v1=[], v2=[], v3=[], v4=[], v5=[]))
        enforcer = casbin.Enforcer(model)
    else:
        enforcer = make_enforcer(PostgresPolicyStore(restricted_engine), seed.ta, model_file=filename)
    args = ["ai", "invoke"] + ([extra] if extra else [])
    assert enforcer.enforce(subject, *args)
    assert not enforcer.enforce("foreign", *args)
    assert all(len(rule) == (4 if extra else 3) for rule in enforcer.get_policy())


@pytest.mark.parametrize("state", ["active", "inactive", "deleted", "unbound", "user_tenant", "group_tenant", "membership_tenant"])
def test_group_resolution_uses_active_subject_and_all_tenant_scopes(restricted_engine, migrated_sync_url, membership, state):
    data = membership
    owner = create_engine(migrated_sync_url)
    with Session(owner) as session:
        user = session.get(User, data.user)
        if state == "inactive":
            user.is_active = False
        elif state == "deleted":
            user.deleted_at = datetime.now(timezone.utc)
        elif state == "unbound":
            user.keycloak_sub = None
        elif state == "user_tenant":
            user.tenant_id = data.foreign
        elif state == "group_tenant":
            session.get(Group, data.group).tenant_id = data.foreign
        elif state == "membership_tenant":
            session.get(UserGroupMembership, data.member).tenant_id = data.foreign
        session.commit()
    owner.dispose()
    assert PostgresMembershipReader(restricted_engine).user_in_group(data.tenant, data.subject, data.group) is (state == "active")
    # A caller cannot substitute the row UUID for the authenticated issuer subject.
    assert not PostgresMembershipReader(restricted_engine).user_in_group(data.tenant, str(data.user), data.group)
    assert not PostgresMembershipReader(restricted_engine).user_in_group(data.foreign, data.subject, data.group)
