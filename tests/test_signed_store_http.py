"""Default standalone application leaves signed writes unavailable until provisioned."""
import pytest


@pytest.mark.asyncio
async def test_unconfigured_signed_storage(http_client, tenant_headers):
    response = await http_client.post("/api/v1/acl/sociacl/keyring/recovery/operations",
                                      headers=tenant_headers, json={})
    assert response.status_code == 503
    assert response.json() == {"detail": "Signed storage is unavailable"}
