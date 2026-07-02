"""--gate/--no-gate: by default the gates are skipped and the run succeeds as
soon as the sanitized bundle is packaged; the new `gate` command re-evaluates
the gates against an already-sanitized bundle.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
SAMPLE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


def _has_gitleaks() -> bool:
    return shutil.which("gitleaks") is not None


def _has_filter_repo() -> bool:
    try:
        import git_filter_repo  # noqa: F401
        return True
    except ImportError:
        return False


requires_tools = pytest.mark.skipif(
    not (_has_gitleaks() and _has_filter_repo()),
    reason="Requires gitleaks and git-filter-repo installed",
)


@pytest.fixture
def sample_repo_git(tmp_path) -> Path:
    repo = tmp_path / "sample_repo"
    shutil.copytree(SAMPLE_REPO, repo)
    for args in (
        ["init"],
        ["config", "user.name", "Test Author"],
        ["config", "user.email", "test@example.com"],
        ["add", "-A"],
        ["commit", "-m", "Initial commit"],
    ):
        subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)
    return repo


@requires_tools
def test_no_gate_succeeds_and_skips_gate_check(tmp_path, sample_repo_git):
    os.environ["REPO_SANITIZER_SALT"] = "test-salt-gate"
    from repo_sanitizer.pipeline import run_sanitize

    out = tmp_path / "out"
    code = run_sanitize(
        source=str(sample_repo_git), out_dir=out, rulepack_path=RULES_DIR, run_gate=False
    )

    # Success == a sanitized bundle was produced, regardless of residual findings.
    assert code == 0
    assert (out / "output" / "sanitized.bundle").is_file()
    result = json.loads((out / "artifacts" / "result.json").read_text())
    assert "gates" not in result, "gate check must be skipped under --no-gate"
    # The bundle SHA is still recorded (orchestrator state tracking relies on it).
    assert result.get("bundle_sha256")


@requires_tools
def test_gate_flag_runs_gate_check(tmp_path, sample_repo_git):
    os.environ["REPO_SANITIZER_SALT"] = "test-salt-gate"
    from repo_sanitizer.pipeline import run_sanitize

    out = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git), out_dir=out, rulepack_path=RULES_DIR, run_gate=True
    )
    result = json.loads((out / "artifacts" / "result.json").read_text())
    assert "gates" in result and "SECRETS" in result["gates"]


@requires_tools
def test_gate_command_evaluates_sanitized_bundle(tmp_path, sample_repo_git):
    os.environ["REPO_SANITIZER_SALT"] = "test-salt-gate"
    from repo_sanitizer.pipeline import run_gate_only, run_sanitize

    # Produce a sanitized bundle (gates off), then re-gate it standalone.
    out1 = tmp_path / "out1"
    run_sanitize(
        source=str(sample_repo_git), out_dir=out1, rulepack_path=RULES_DIR, run_gate=False
    )
    bundle = out1 / "output" / "sanitized.bundle"
    assert bundle.is_file()

    out2 = tmp_path / "out2"
    code = run_gate_only(source=str(bundle), out_dir=out2, rulepack_path=RULES_DIR)

    result = json.loads((out2 / "artifacts" / "result.json").read_text())
    assert "gates" in result and "SECRETS" in result["gates"]
    # The deterministic leak gate must be green on an already-sanitized bundle.
    assert result["gates"]["SECRETS"]["passed"]
    # Structural gates must not false-fail in standalone mode: the bundle's
    # branches ARE its intake set (no ref-reconcile ran to build a rename map).
    assert result["gates"]["BRANCHES_PRESERVED"]["passed"], (
        result["gates"]["BRANCHES_PRESERVED"]
    )
    assert isinstance(code, int)
