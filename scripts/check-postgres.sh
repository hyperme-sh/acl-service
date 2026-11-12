#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'PostgreSQL qualification runs only in CI' >&2; exit 1; }
cd "$(dirname "$0")/.."
schema_checkout=$(mktemp -d)
trap 'rm -rf "$schema_checkout"' EXIT
git -C "$schema_checkout" init --quiet
git -C "$schema_checkout" remote add origin https://github.com/hyperme-sh/controlplane-db.git
git -C "$schema_checkout" fetch --quiet --depth 1 origin 30efb83649e2ff4db7b3d568ea06a81a2b04468d
git -C "$schema_checkout" checkout --quiet --detach 30efb83649e2ff4db7b3d568ea06a81a2b04468d
export SOCIACL_CONTACT_SCHEMA="$schema_checkout/src/controlplane_db/migration_chains/platform/versions/0086_contact_lanes.py"
export SOCIACL_FIRST_CONTACT_SCHEMA="$schema_checkout/src/controlplane_db/migration_chains/platform/versions/0087_first_contact.py"
unset PYTHONPATH UV_NO_SYNC
uv sync --frozen --no-editable
if [[ -n "${RELEASE_CANDIDATE_DIR:-}" ]]; then
  uv pip install --python .venv/bin/python --no-deps --reinstall "$RELEASE_CANDIDATE_DIR"/*.whl
fi
# Isolated Python must import the installed distribution, never checkout source.
uv run --no-sync python -I -c 'import acl_service; assert "/site-packages/" in acl_service.__file__, acl_service.__file__'
uv run --no-sync python -I -m pytest integration -v
