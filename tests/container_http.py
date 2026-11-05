"""Exercise the installed image's real routes with fake auth, storage and events.

Run with scripts/check-image.sh. No source checkout supplies acl_service imports.
PostgreSQL/RLS and live identity acceptance are deliberately not claimed here.
"""
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import unittest
import uuid

from fastapi.testclient import TestClient
from auth_service.schemas import AuthMeResponse
from spanopticon_models.sociacl import SociACLShareMode, PoliticalViewCategory

RELEASE_MODE = next(mode.value for mode in SociACLShareMode if mode.value not in ("notify_only", "negotiate"))
from acl_service import deps, middleware
from acl_service.app import create_app
from acl_service.domain import sociacl_evaluator
from acl_service.infrastructure import enforcer_factory
from acl_service.interfaces.api import routes, sociacl_routes


class ImageHTTPTests(unittest.TestCase):
    def setUp(self):
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        session = AsyncMock()
        session.__aenter__.return_value = session
        self.patches.enter_context(patch.object(middleware, "get_session_maker", return_value=lambda: session))
        self.patches.enter_context(patch.object(middleware, "set_current_tenant_id_guc", AsyncMock()))
        self.tenant = uuid.uuid4()
        self.app = create_app()
        self.app.state.sync_engine = object()
        self.app.state.policy_store = object()
        self.user = AuthMeResponse(sub="verified-user", tenant_id=self.tenant)
        self.app.dependency_overrides[deps.get_current_user] = lambda: self.user
        self.app.dependency_overrides[deps.get_current_tenant_from_token] = lambda: self.tenant
        self.app.dependency_overrides[deps.optional_authenticated_user] = lambda: self.user
        # Do not enter lifespan: its real DB/event setup is outside this fixture.
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        self.headers = {"X-Tenant-ID": str(self.tenant)}

    def test_policy_self_grant_and_delete_need_existing_manage_permission(self):
        enforce = self.patches.enter_context(patch.object(enforcer_factory, "enforce_rbac", return_value=False))
        add = self.patches.enter_context(patch.object(routes, "add_rule"))
        remove = self.patches.enter_context(patch.object(routes, "delete_rule"))
        for method in ("POST", "DELETE"):
            with self.subTest(method=method):
                response = self.client.request(method, "/api/v1/acl/policies", headers=self.headers,
                    json={"ptype": "p", "rule": ["user:verified-user", "/acl/policies", "manage"]})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(enforce.call_args.args[1:],
                                 (self.tenant, "user:verified-user", "/acl/policies", "manage"))
        add.assert_not_called()
        remove.assert_not_called()

    def test_policy_tenant_mismatch_stops_before_authorization(self):
        enforce = self.patches.enter_context(patch.object(enforcer_factory, "enforce_rbac"))
        response = self.client.post("/api/v1/acl/policies", headers={"X-Tenant-ID": str(uuid.uuid4())},
            json={"ptype": "p", "rule": ["user:verified-user", "/acl/policies", "manage"]})
        self.assertEqual(response.status_code, 403, response.text)
        enforce.assert_not_called()

    def test_existing_administrator_can_create_and_delete_policy(self):
        self.patches.enter_context(patch.object(enforcer_factory, "enforce_rbac", return_value=True))
        row = SimpleNamespace(id=1, ptype="p", v0="user:verified-user", v1="resource",
                              v2="read", v3=None, v4=None, v5=None)
        add = self.patches.enter_context(patch.object(routes, "add_rule", return_value=row))
        remove = self.patches.enter_context(patch.object(routes, "delete_rule", return_value=True))
        self.patches.enter_context(patch.object(routes, "_emit_policy_updated", AsyncMock()))
        for method, expected in (("POST", 201), ("DELETE", 204)):
            response = self.client.request(method, "/api/v1/acl/policies", headers=self.headers,
                json={"ptype": "p", "rule": ["user:verified-user", "resource", "read"]})
            self.assertEqual(response.status_code, expected, response.text)
        add.assert_called_once()
        remove.assert_called_once()

    def prepare_share(self, predicate):
        link = SimpleNamespace(id=uuid.uuid4(), tenant_id=self.tenant, revoked_at=None,
            expires_at=None, uses_remaining=None, predicate_json=predicate, mode=RELEASE_MODE)
        self.patches.enter_context(patch.object(sociacl_routes, "lookup_share_by_token_hash", return_value=link))
        publisher = SimpleNamespace(publish=AsyncMock())
        self.patches.enter_context(patch.object(sociacl_routes, "get_tenant_event_publisher", return_value=publisher))
        decrement = self.patches.enter_context(patch.object(sociacl_routes, "decrement_uses"))
        return publisher, decrement

    def evaluate(self, context):
        response = self.client.post("/api/v1/acl/sociacl/evaluate", json={"token": "synthetic-share", "context": context})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_group_checks_use_only_verified_same_tenant_subject(self):
        publisher, decrement = self.prepare_share({"member_of_group_id": str(uuid.uuid4())})
        membership = self.patches.enter_context(patch.object(sociacl_evaluator, "_user_in_group", return_value=True))
        for identity in (None, AuthMeResponse(sub="foreign", tenant_id=uuid.uuid4()), self.user):
            with self.subTest(identity=identity):
                self.app.dependency_overrides[deps.optional_authenticated_user] = lambda: identity
                result = self.evaluate({"sub": "spoofed-group-owner"})
                self.assertEqual(result["decision"], "allow" if identity is self.user else "deny")
                if identity is not self.user:
                    membership.assert_not_called()
                    decrement.assert_not_called()
                    self.assertIsNone(publisher.publish.call_args.kwargs["payload"]["actor_sub"])
        self.assertEqual(membership.call_args.args[1:3], (self.tenant, "verified-user"))
        self.assertEqual(publisher.publish.call_args.kwargs["payload"]["actor_sub"], "verified-user")

    def test_self_asserted_predicates_never_release_shares(self):
        for predicate in ({"min_verification_level": 0}, {"min_vouch_count": 0},
                          {"required_political_tolerance": next(iter(PoliticalViewCategory)).value},
                          {"max_distance_km": 1}, {"cross_network_handle_allowlist": []},
                          {"cross_network_handle_blocklist": []}):
            with self.subTest(predicate=predicate), ExitStack() as patches:
                link = SimpleNamespace(id=uuid.uuid4(), tenant_id=self.tenant, revoked_at=None,
                    expires_at=None, uses_remaining=None, predicate_json=predicate, mode=RELEASE_MODE)
                patches.enter_context(patch.object(sociacl_routes, "lookup_share_by_token_hash", return_value=link))
                patches.enter_context(patch.object(sociacl_routes, "get_tenant_event_publisher",
                    return_value=SimpleNamespace(publish=AsyncMock())))
                decrement = patches.enter_context(patch.object(sociacl_routes, "decrement_uses"))
                result = self.evaluate({"sub": "spoofed", "verification_level": 4, "vouch_count": 100})
                self.assertEqual(result["decision"], "deny")
                self.assertIn(result["reason_code"],
                              ("verified_identity_attributes_required", "verified_predicate_evidence_required"))
                decrement.assert_not_called()


if __name__ == "__main__":
    unittest.main()
