"""Initialize once from a standalone, independently digest-pinned SQLite backup."""
import argparse
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile


def initialize(snapshot: Path, expected: str, output: Path):
    with tempfile.TemporaryDirectory(dir=output.parent) as directory:
        copy = Path(directory) / "snapshot"
        digest = hashlib.sha256()
        with snapshot.open("rb") as source, copy.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                target.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("snapshot differs from independent checkpoint")
        new = Path(directory) / "freshness"
        with closing(sqlite3.connect(copy.resolve().as_uri() + "?immutable=1", uri=True)) as source, \
                closing(sqlite3.connect(new)) as target, target:
            target.execute("CREATE TABLE ciphertext_heads(principal TEXT NOT NULL, kind TEXT NOT NULL, "
                           "generation INTEGER NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(principal, kind))")
            for principal, in source.execute("SELECT principal FROM history_accounts"):
                for kind in ("recovery", "wraps"):
                    row = source.execute("SELECT generation,payload FROM history_ciphertext "
                                         "WHERE principal=? AND kind=?", (principal, kind)).fetchone()
                    generation, payload = row if row is not None else (0, b"")
                    target.execute("INSERT INTO ciphertext_heads VALUES(?,?,?,?)",
                                   (principal, kind, generation, hashlib.sha256(payload).digest()))
        new.chmod(0o600)
        os.link(new, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    initialize(args.snapshot, args.sha256, args.output)
