"""Trusted, default-off configuration for public signed-policy delivery."""
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from acl_service.infrastructure.witness_policy_export import export_signed_policy
from acl_service.infrastructure.witness_policy_ingest import MAX_POLICY_BYTES

PUBLIC_POLICY_PATH = "/api/v1/acl/sociacl/witness-policy"
CONFIG_NAMES = (
    "SOCIACL_WITNESS_POLICY_PAYLOAD_FILE",
    "SOCIACL_WITNESS_POLICY_SIGNATURE_FILE",
    "SOCIACL_WITNESS_POLICY_ROOT_FILE",
    "SOCIACL_WITNESS_POLICY_AUDIENCE",
)


def read_regular_file(path: Path, limit: int) -> bytes:
    # A bad mount must not block a request on a FIFO/device or read unbounded data.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular file required")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized publication input")
    return data


@dataclass(frozen=True)
class WitnessPolicyPublication:
    payload_file: Path
    signature_file: Path
    root_key: ec.EllipticCurvePublicKey
    audience: str

    def export(self, engine) -> dict:
        # Reload signed bytes on every request; never serve a cached last-good
        # bundle after the installed revision changes or the transport expires.
        payload = read_regular_file(self.payload_file, MAX_POLICY_BYTES)
        signature = read_regular_file(self.signature_file, 64)
        return export_signed_policy(engine, payload, signature, self.root_key, self.audience)


def load_publication(environ: Mapping[str, str] | None = None) -> WitnessPolicyPublication | None:
    source = os.environ if environ is None else environ
    values = [source.get(name, "") for name in CONFIG_NAMES]
    if not any(values):
        return None
    try:
        if not all(values):
            raise ValueError("incomplete configuration")
        payload, signature, root_file = (Path(value) for value in values[:3])
        if not all(path.is_absolute() for path in (payload, signature, root_file)):
            raise ValueError("absolute paths required")
        root = load_pem_public_key(read_regular_file(root_file, 16384))
        if not isinstance(root, ec.EllipticCurvePublicKey) or not isinstance(root.curve, ec.SECP256R1):
            raise ValueError("P-256 public root required")
        return WitnessPolicyPublication(payload, signature, root, values[3])
    except Exception:
        # Startup errors must not include paths, PEM bytes or configuration values.
        raise RuntimeError("Invalid witness policy publication configuration") from None
