#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
uv sync --frozen --no-editable
if [[ -n "${RELEASE_CANDIDATE_DIR:-}" ]]; then
  uv pip install --python .venv/bin/python --no-deps --reinstall "$RELEASE_CANDIDATE_DIR"/*.whl
fi
# Isolated Python must import the installed distribution, never checkout source.
uv run --no-sync python -I -c 'import acl_service; assert "/site-packages/" in acl_service.__file__, acl_service.__file__'
uv run --no-sync python -I -m pytest integration -v
