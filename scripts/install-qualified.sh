#!/usr/bin/env bash
# Install the application with the current public lock and explicit overrides.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ $# != 2 ]]; then echo 'Usage: install-qualified.sh PYTHON APPLICATION_WHEEL' >&2; exit 2; fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
uv export --project "$root" --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
python3 "$root/scripts/export_selected_overrides.py" "$root/pyproject.toml" "$scratch/overrides.txt"
options=(--constraint "$scratch/requirements.txt")
if [[ -s "$scratch/overrides.txt" ]]; then options+=(--overrides "$scratch/overrides.txt"); fi
uv pip install --no-config --python "$1" "${options[@]}" "$2"
