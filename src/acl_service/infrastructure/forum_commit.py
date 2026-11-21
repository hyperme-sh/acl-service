"""Fixed-origin Plane decisions inside the checked statement transaction."""
import hashlib
import http.client
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit

from acl_service.domain.history_store import AdmissionRejected, HistoryConflict

REQUEST_SECONDS = 0.65


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
        payload = {
            "host": parsed.hostname, "port": parsed.port or 443,
            "path": f'/api/v1/hypermesh/bots/{update["botId"]}/forum/authorize-update',
            "headers": {"Authorization": "Bearer " + key, "X-Tenant-ID": str(tenant),
                        "Content-Type": "application/json", "Accept-Encoding": "identity"},
            "body": dict(version=1, forum_id=forum, principal=update["principal"],
                         assignment_id=update["assignmentId"], session_id=update["sessionId"],
                         task_id=update["taskId"], delivery_id=update["deliveryId"],
                         sequence=update["sequence"], status=update["status"], digest=digest),
        }
        # The subprocess deadline bounds DNS, TLS, headers and body together.
        # Timeout kills and reaps the worker before the SQLite lock is released.
        try:
            result = subprocess.run(
                [sys.executable, "-m", "acl_service.infrastructure.forum_commit"],
                input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=REQUEST_SECONDS, check=False,
            )
            if result.returncode or len(result.stdout) > 1030:
                raise HistoryConflict("Plane decision unavailable")
            status, _, body = result.stdout.partition(b"\n")
            if status in (b"403", b"409"):
                raise AdmissionRejected("Plane refused the forum delivery")
            if status != b"200" or json.loads(body) != {"version": 1, "digest": digest}:
                raise HistoryConflict("Plane decision differs")
        except (AdmissionRejected, HistoryConflict):
            raise
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise HistoryConflict("Plane decision unavailable") from None

    return decide


def _request():
    payload = json.loads(sys.stdin.buffer.read(8193))
    conn = http.client.HTTPSConnection(payload["host"], payload["port"], timeout=REQUEST_SECONDS)
    try:
        conn.request("POST", payload["path"], body=json.dumps(payload["body"]).encode(), headers=payload["headers"])
        response = conn.getresponse()
        result = response.read(1025) if response.status == 200 else b""
        sys.stdout.buffer.write(str(response.status).encode() + b"\n" + result)
    finally:
        conn.close()


if __name__ == "__main__":
    _request()
