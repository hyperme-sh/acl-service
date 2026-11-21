"""Fixed-origin Plane decisions inside the checked statement transaction."""
import asyncio
import hashlib
import json
import re
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict

REQUEST_SECONDS = 0.65


def plane_forum_commit(origin, tenant, forum, key, *, transport=None):
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or parsed.geturl() != origin or not re.fullmatch(r"hm_fcm_[a-f0-9]{64}", key)):
        raise ValueError("invalid forum commit authority")

    async def decide(update):
        if update["tenant"] != str(tenant) or update["forumId"] != forum:
            raise AdmissionRejected("forum commit authority scope differs")
        bot = UUID(update["botId"])
        if not bot.int:
            raise AdmissionRejected("forum commit bot differs")
        canonical = json.dumps(update, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        body = dict(version=1, forum_id=forum, principal=update["principal"],
                    assignment_id=update["assignmentId"], session_id=update["sessionId"],
                    task_id=update["taskId"], delivery_id=update["deliveryId"],
                    sequence=update["sequence"], status=update["status"], digest=digest)
        target = f"{origin}/api/v1/hypermesh/bots/{bot}/forum/authorize-update"
        headers = {"Authorization": "Bearer " + key, "X-Tenant-ID": str(tenant), "Accept-Encoding": "identity"}
        try:
            async with asyncio.timeout(REQUEST_SECONDS):
                async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                             transport=transport, timeout=REQUEST_SECONDS) as client:
                    async with client.stream("POST", target, json=body, headers=headers) as response:
                        if response.status_code in (403, 409):
                            raise AdmissionRejected("Plane refused the forum delivery")
                        if response.status_code != 200:
                            raise HistoryConflict("Plane decision unavailable")
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(data) + len(chunk) > 1024:
                                raise HistoryConflict("Plane decision differs")
                            data.extend(chunk)
                        if json.loads(data) != {"version": 1, "digest": digest}:
                            raise HistoryConflict("Plane decision differs")
        except (AdmissionRejected, HistoryConflict):
            raise
        except (ValueError, TimeoutError, httpx.HTTPError):
            raise HistoryConflict("Plane decision unavailable") from None

    return decide
