from pathlib import Path
import os
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_install_drops_inherited_credentials(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'test-only')
    monkeypatch.setenv('DEPENDENCY_READ_TOKEN', 'test-only')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'test-only')
    captured = []
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: captured.append((args, kwargs)))
    runpy.run_path(str(ROOT / 'scripts/install-image-runtime.py'))
    args, kwargs = captured[0]
    assert args[0] == ['uv', 'sync', '--frozen', '--no-dev', '--no-editable', '--no-cache']
    assert kwargs['check']
    for key in ('GITHUB_TOKEN', 'DEPENDENCY_READ_TOKEN', 'GIT_CONFIG_VALUE_0'):
        assert key not in kwargs['env']
    assert kwargs['env']['GIT_CONFIG_GLOBAL'] == '/dev/null'


def test_runtime_transport_is_qualified_ghcr_with_no_actions_archives():
    workflow = (ROOT / '.github/workflows/package.yml').read_text()
    assert 'upload-artifact' not in workflow and 'download-artifact' not in workflow
    assert 'create-github-app-token' not in workflow
    assert '--channel test --publish' in workflow
    assert 'needs: image' in workflow and 'needs: package' in workflow
    assert 'EXPECTED_IMAGE_ID' in workflow
    assert 'scripts/check-runtime-startup.py' in workflow
    assert '"$current" != "$GITHUB_SHA"' in workflow
    assert 'workflow_dispatch:' not in workflow
    assert 'env GITHUB_ACTIONS="$GITHUB_ACTIONS" RELEASE_CANDIDATE_DIR=' in workflow
