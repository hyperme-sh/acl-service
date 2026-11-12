"""Public request transport. Storage never accepts a contact or grants access."""
import hashlib
import re

from sqlalchemy import text

LANE_PATH = re.compile(r"/api/v1/acl/sociacl/first-contact/[0-9a-f]{64}/messages")
MAX_CIPHERTEXT = 8192
MAX_LANE_BYTES = 1024 * 1024
MAX_LANE_MESSAGES = 128
MAX_GLOBAL_BYTES = 32 * 1024 * 1024
MAX_GLOBAL_MESSAGES = 4096
MAX_WRITES_PER_MINUTE = 10


def is_first_contact_path(path: str, method: str) -> bool:
    return method in {"GET", "POST"} and LANE_PATH.fullmatch(path) is not None


def validate_lane(lane: str) -> None:
    if not isinstance(lane, str) or re.fullmatch(r"[0-9a-f]{64}", lane) is None:
        raise ValueError("Invalid opaque lane id")


def message_id(ciphertext: bytes) -> str:
    if not isinstance(ciphertext, bytes) or not 94 <= len(ciphertext) <= MAX_CIPHERTEXT:
        raise ValueError("Invalid ciphertext size")
    return hashlib.sha256(ciphertext).hexdigest()


class LaneCapacity(Exception):
    pass


def require_capacity(totals, size: int) -> None:
    if (totals["total"] >= MAX_GLOBAL_MESSAGES or totals["bytes"] + size > MAX_GLOBAL_BYTES
            or totals["lane_total"] >= MAX_LANE_MESSAGES or totals["lane_bytes"] + size > MAX_LANE_BYTES
            or totals["recent"] >= MAX_WRITES_PER_MINUTE):
        raise LaneCapacity()


class PostgresFirstContactStore:
    def __init__(self, engine):
        self.engine = engine

    def append(self, lane: str, ciphertext: bytes) -> str:
        validate_lane(lane)
        digest = message_id(ciphertext)
        with self.engine.begin() as cx:
            # One shared transaction lock makes global and per-lane quotas atomic
            # across processes. The table is capped at 4096 rows / 32 MiB.
            cx.execute(text("SELECT pg_advisory_xact_lock(73622570)"))
            now = cx.execute(text("SELECT clock_timestamp()" )).scalar_one()
            cx.execute(text("DELETE FROM sociacl_first_contact_messages WHERE expires_at <= :now"), {"now": now})
            if cx.execute(text("SELECT 1 FROM sociacl_first_contact_messages WHERE lane_id=:lane AND message_id=:id"),
                          {"lane": lane, "id": digest}).first():
                return digest  # Retries neither consume quota nor extend expiry.
            totals = cx.execute(text("""
                SELECT count(*) AS total, coalesce(sum(byte_size),0) AS bytes,
                    count(*) FILTER (WHERE lane_id=:lane) AS lane_total,
                    coalesce(sum(byte_size) FILTER (WHERE lane_id=:lane),0) AS lane_bytes,
                    count(*) FILTER (WHERE lane_id=:lane AND created_at > :now - interval '1 minute') AS recent
                FROM sociacl_first_contact_messages
            """), {"lane": lane, "now": now}).mappings().one()
            require_capacity(totals, len(ciphertext))
            cx.execute(text("""
                INSERT INTO sociacl_first_contact_messages (lane_id,message_id,ciphertext,created_at,expires_at)
                VALUES (:lane,:id,:ciphertext,:now,:now + interval '7 days')
            """), {"lane": lane, "id": digest, "ciphertext": ciphertext, "now": now})
        return digest

    def read(self, lane: str) -> list[dict]:
        validate_lane(lane)
        with self.engine.connect() as cx:
            rows = cx.execute(text("""
                SELECT message_id, ciphertext FROM sociacl_first_contact_messages
                WHERE lane_id=:lane AND expires_at > clock_timestamp()
                ORDER BY created_at, message_id LIMIT 128
            """), {"lane": lane}).mappings().all()
            return [{"id": r["message_id"], "ciphertext": bytes(r["ciphertext"])} for r in rows]
