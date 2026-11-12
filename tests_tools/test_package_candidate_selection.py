"""Exercise the actual package-script candidate gate with a recording verifier."""
import os
from pathlib import Path
import re
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check-package.sh"


@pytest.mark.parametrize("ref,explicit,called", [("branch", "0", False), ("", "0", False),
    ("tag", "0", True), ("branch", "1", True), ("tag", "1", True)])
def test_candidate_is_exact_checked_for_tags_or_explicit_qualification(tmp_path, ref, explicit, called):
    function = re.search(r"^verify_declared_candidate\(\) \{.*?^\}", SCRIPT.read_text(), re.M | re.S).group()
    recorder = tmp_path / "python3"
    recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALLS"\nexit "${VERIFIER_STATUS:-0}"\n')
    recorder.chmod(0o755)
    output = tmp_path / "calls"
    env = {**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"], "CALLS": str(output),
           "GITHUB_REF_TYPE": ref, "VERIFY_RELEASE_CANDIDATE": explicit}
    command = function + '\nscratch=/synthetic\nverify_declared_candidate\n'
    result = subprocess.run(["bash", "-e", "-c", command], env=env, capture_output=True)
    assert result.returncode == 0
    assert output.exists() == called
    if called:
        args = output.read_text().splitlines()
        assert args[:2] == ["scripts/verify_release_candidate.py", "releases/candidate/release.json"]
        assert not any("qualification/current" in arg for arg in args)
        env["VERIFIER_STATUS"] = "1"
        assert subprocess.run(["bash", "-e", "-c", command], env=env, capture_output=True).returncode == 1


def test_candidate_gate_rejects_malformed_selection(tmp_path):
    function = re.search(r"^verify_declared_candidate\(\) \{.*?^\}", SCRIPT.read_text(), re.M | re.S).group()
    env = {**os.environ, "VERIFY_RELEASE_CANDIDATE": "false"}
    assert subprocess.run(["bash", "-e", "-c", function + "\nverify_declared_candidate"], env=env, capture_output=True).returncode == 2
