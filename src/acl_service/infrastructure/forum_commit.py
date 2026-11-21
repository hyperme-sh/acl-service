"""Fixed-origin Plane decisions inside the checked statement transaction."""
import hashlib
import http.client
import json
import re
from urllib.parse import urlsplit

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict


def plane_forum_commit(origin, tenant, forum, key):
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or parsed.geturl() != origin or not re.fullmatch(r"hm_fcm_[a-f0-9]{64}", key)):
        raise ValueError("invalid forum commit authority")

    def decide(update):
        if update["tenant"] != str(tenant) or update["forumId"] != forum:
            raise AdmissionRejected("forum commit authority scope differs")
        canonical = json.dumps(update, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        body = json.dumps(dict(
            version=1, forum_id=forum, principal=update["principal"], assignment_id=update["assignmentId"],
            session_id=update["sessionId"], task_id=update["taskId"], delivery_id=update["deliveryId"],
            sequence=update["sequence"], status=update["status"], digest=digest,
        )).encode()
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=0.65)
        try:
            conn.request("POST", f'/api/v1/hypermesh/bots/{update["botId"]}/forum/authorize-update',
                         body=body, headers={"Authorization": "Bearer " + key, "X-Tenant-ID": str(tenant),
                                             "Content-Type": "application/json", "Accept-Encoding": "identity"})
            response = conn.getresponse()
            if response.status in (403, 409):
                raise AdmissionRejected("Plane refused the forum delivery")
            if response.status != 200:
                raise HistoryConflict("Plane decision unavailable")
            result = response.read(1025)
            if len(result) > 1024 or json.loads(result) != {"version": 1, "digest": digest}:
                raise HistoryConflict("Plane decision differs")
        except (AdmissionRejected, HistoryConflict):
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise HistoryConflict("Plane decision unavailable") from None
        finally:
            conn.close()

    return decide
