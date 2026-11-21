import asyncio
import json
from uuid import uuid4

import httpx
import pytest

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure import forum_commit


@pytest.mark.asyncio
async def test_plane_decision_uses_bound_origin_digest_and_no_redirect():
    tenant, bot = uuid4(), str(uuid4())
    key = "hm_fcm_" + "a" * 64
    update = dict(tenant=str(tenant), forumId="forum-owner", principal="owner", botId=bot,
                  assignmentId=bot, sessionId=bot, taskId=bot, deliveryId=bot,
                  sequence=1, status="completed", signature="SEA-fixture")
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        assert str(request.url) == f"https://plane.example.test/api/v1/hypermesh/bots/{bot}/forum/authorize-update"
        assert request.headers["authorization"] == "Bearer " + key
        assert request.headers["x-tenant-id"] == str(tenant)
        body = json.loads(request.content)
        assert body["status"] == "completed" and "signature" not in body
        if calls == 1:
            return httpx.Response(302, headers={"Location": "https://other.example.test"})
        return httpx.Response(200, json={"version": 1, "digest": body["digest"]})

    decide = forum_commit.plane_forum_commit("https://plane.example.test", tenant, "forum-owner", key,
                                             transport=httpx.MockTransport(handler))
    with pytest.raises(HistoryConflict):
        await decide(update)
    assert calls == 1
    await decide(update)
    with pytest.raises(AdmissionRejected):
        await decide({**update, "forumId": "elsewhere"})
    assert calls == 2


@pytest.mark.asyncio
async def test_slow_body_is_cancelled_by_total_deadline(monkeypatch):
    monkeypatch.setattr(forum_commit, "REQUEST_SECONDS", 0.05)
    tenant, bot = uuid4(), str(uuid4())
    closed = asyncio.Event()

    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(20):
                await asyncio.sleep(0.01)
                yield b" "

        async def aclose(self):
            closed.set()

    decide = forum_commit.plane_forum_commit("https://plane.example.test", tenant, "forum-owner",
        "hm_fcm_" + "a" * 64, transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowBody())))
    with pytest.raises(HistoryConflict):
        await decide(dict(tenant=str(tenant), forumId="forum-owner", principal="owner", botId=bot,
                          assignmentId=bot, sessionId=bot, taskId=bot, deliveryId=bot,
                          sequence=1, status="completed"))
    assert closed.is_set()
