"""Canonical digest of the complete single-host authority snapshot."""
import hashlib


def authority_digest(db):
    digest = hashlib.sha256(b"acl-authority-snapshot-v1\0")
    for table, columns, order in (
        ("history_accounts", "principal,genesis", "principal"),
        ("history_entries", "principal,revision,entry", "principal,revision"),
        ("history_head_floors", "principal,head", "principal"),
    ):
        digest.update(b"T" + table.encode() + b"\0")
        for row in db.execute(f"SELECT {columns} FROM main.{table} ORDER BY {order}"):
            digest.update(b"R")
            for value in row:
                if isinstance(value, bytes):
                    tag, data = b"B", value
                elif isinstance(value, str):
                    tag, data = b"S", value.encode("utf-8")
                elif isinstance(value, int):
                    tag, data = b"I", str(value).encode("ascii")
                else:
                    raise ValueError("invalid authority field")
                digest.update(tag + len(data).to_bytes(8, "big"))
                digest.update(data)
    return digest.digest()
