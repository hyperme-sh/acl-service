"""Offline operator entry point: python -m acl_service.witness_policy_cli."""
import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy import create_engine

from acl_service.infrastructure.db_url import sync_database_url
from acl_service.infrastructure.witness_policy_export import export_signed_policy
from acl_service.infrastructure.witness_policy_ingest import MAX_POLICY_BYTES, install_signed_policy, verify_policy


def _read(path, limit):
    with Path(path).open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("oversized input")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify and install an operator-signed witness policy")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--signature", required=True, help="64-byte compact ES256 signature file")
    parser.add_argument("--root-key", required=True, help="independently provisioned public PEM")
    parser.add_argument("--audience", required=True, help="trusted deployment audience")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--export", action="store_true", help="export a verified bundle matching installed policy")
    mode.add_argument("--check", action="store_true", help="verify only; do not connect to the database")
    args = parser.parse_args(argv)
    engine = None
    try:
        payload = _read(args.policy, MAX_POLICY_BYTES)
        signature = _read(args.signature, 64)
        root = load_pem_public_key(_read(args.root_key, 16384))
        verified = verify_policy(payload, signature, root, args.audience)
        if args.check:
            print(json.dumps({"verifiedRevision": verified.revision, "installed": False}))
            return 0
        engine = create_engine(sync_database_url(os.environ["DATABASE_URL"]))
        if args.export:
            print(json.dumps(export_signed_policy(engine, payload, signature, root, args.audience)))
            return 0
        installed = install_signed_policy(engine, payload, signature, root, args.audience)
        print(json.dumps({"installedRevision": installed.revision, "installed": True}))
        return 0
    except Exception:
        # Do not print policy contents, credentials, root material, or SQL errors.
        print("witness policy rejected")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
