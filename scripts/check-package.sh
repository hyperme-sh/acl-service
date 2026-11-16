#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC SKIP_TESTCONTAINERS
if (( $# )); then echo 'Usage: bash scripts/check-package.sh' >&2; exit 2; fi
check_lock() { uv lock --check; }
sync_environment() {
  uv sync --frozen --python 3.13
  "${UV_PROJECT_ENVIRONMENT:-$PWD/.venv}/bin/python" scripts/verify_preparation_environment.py "$PWD"
}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
if [[ -n "${RELEASE_CANDIDATE_DIR:-}" ]]; then
  # This is a disposable copy of the job-local candidate, never an upload source.
  mkdir -p "$scratch/dist"
  cp "$RELEASE_CANDIDATE_DIR"/*.whl "$RELEASE_CANDIDATE_DIR"/*.tar.gz "$scratch/dist/"
else
  check_lock
  sync_environment
  uv run --frozen pytest --junitxml="$scratch/source.xml"
  uv build --out-dir "$scratch/dist"
fi
# Validate the fresh candidate before running any source tests or installing code.
distribution_hashes=$(cd "$scratch/dist" && sha256sum -- *.whl *.tar.gz)
python3 scripts/verify_wheel.py "$scratch/dist"
python3 scripts/export_release_contract.py "$scratch"/dist/*.whl --output "$scratch/contract"
verify_declared_candidate() {
  case "${VERIFY_RELEASE_CANDIDATE:-0}" in
    0|1) ;;
    *) echo 'VERIFY_RELEASE_CANDIDATE must be 0 or 1' >&2; return 2 ;;
  esac
  # Development wheels are new bytes. Historical qualification is not their candidate.
  if [[ "${GITHUB_REF_TYPE:-}" != tag && "${VERIFY_RELEASE_CANDIDATE:-0}" != 1 ]]; then
    return 0
  fi
  qualified_manifest=releases/candidate/release.json
    python3 scripts/verify_release_candidate.py "$qualified_manifest" "$scratch/contract/contract.json" "$scratch/contract/evidence.json" acl-service
}
verify_declared_candidate
check_lock
sync_environment
if [[ -n "${RELEASE_CANDIDATE_DIR:-}" ]]; then
  uv run --frozen pytest --junitxml="$scratch/source.xml"
fi
uv run --frozen pytest -q tests_tools
uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
uv pip uninstall --python "$scratch/venv/bin/python" spanopticon-models auth-service controlplane-core controlplane-api controlplane-tenancy controlplane-identity controlplane-db controlplane-events operator-ban-store
bash scripts/install-qualified.sh "$scratch/venv/bin/python" "$scratch"/dist/*.whl
cp -R tests_artifacts "$scratch/"
cp -R tests "$scratch/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests --junitxml="$scratch/wheel.xml")
# Rebuild from the sdist; a checkout must not supply omitted package files.
uv run --frozen python - "$scratch" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(next((root / 'dist').glob('*.tar.gz'))) as archive:
    archive.extractall(root / 'sdist', filter='data')
PY
uv build --wheel "$scratch"/sdist/* --out-dir "$scratch/rebuilt"
uv run --frozen python scripts/verify_wheel.py "$scratch/rebuilt"
python3 scripts/export_release_contract.py "$scratch"/rebuilt/*.whl --output "$scratch/rebuilt-contract"
cmp "$scratch/contract/contract.json" "$scratch/rebuilt-contract/contract.json"
uv pip install --no-config --python "$scratch/venv/bin/python" --no-deps --reinstall "$scratch"/rebuilt/*.whl
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests --junitxml="$scratch/sdist.xml")

# Installed tests may inspect these files, but must not replace validated bytes.
(cd "$scratch/dist" && sha256sum --check <<< "$distribution_hashes")

python3 scripts/verify-test-results.py "$scratch/source.xml" "$scratch/wheel.xml" "$scratch/sdist.xml"

if [[ -n "${PREPARATION_EVIDENCE_DIR:-}" ]]; then
  python3 scripts/export_release_contract.py "$scratch"/dist/*.whl --output "$PREPARATION_EVIDENCE_DIR"
  cp "$scratch/source.xml" "$scratch/wheel.xml" "$scratch/sdist.xml" "$PREPARATION_EVIDENCE_DIR/"
fi
