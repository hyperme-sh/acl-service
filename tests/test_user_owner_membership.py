import json
import unittest
from unittest.mock import patch
from uuid import UUID

import httpx

from acl_service.infrastructure.membership_reader import MembershipOwnerUnavailable, UserOwnerMembershipReader


class UserOwnerMembershipTests(unittest.TestCase):
    tenant = UUID("00000000-0000-4000-8000-000000000001")
    group = UUID("00000000-0000-4000-8000-000000000002")

    def lookup(self, handler):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        reader = UserOwnerMembershipReader("https://user.example.test", "only-for-membership")
        with patch("httpx.Client", return_value=client) as factory:
            result = reader.user_in_group(self.tenant, "verified-user", self.group)
            factory.assert_called_once_with(timeout=5, follow_redirects=False, trust_env=False)
            return result

    def test_reads_the_exact_verified_subject_and_tenant(self):
        def respond(request):
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/api/v1/internal/acl/group-membership")
            self.assertEqual(request.headers["authorization"], "Bearer only-for-membership")
            self.assertEqual(request.headers["x-tenant-id"], str(self.tenant))
            self.assertEqual(json.loads(request.content), {
                "tenant_id": str(self.tenant), "subject": "verified-user", "group_id": str(self.group),
            })
            return httpx.Response(200, json={"member": False})

        self.assertIs(self.lookup(respond), False)

    def test_does_not_treat_refusal_transport_or_invalid_body_as_membership(self):
        cases = [
            (302, {"member": True}), (403, {"member": True}), (503, {"member": True}),
            (200, {"member": "true"}), (200, {"member": True, "other": True}),
        ]
        for status, body in cases:
            with self.subTest(status=status, body=body), self.assertRaises(MembershipOwnerUnavailable):
                self.lookup(lambda _: httpx.Response(status, json=body))
