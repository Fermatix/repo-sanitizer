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
    """Create a proper git repo from the fixture files."""
    repo = tmp_path / "sample_repo"
    shutil.copytree(SAMPLE_REPO, repo)
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test Author"],
        cwd=str(repo), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo), check=True, capture_output=True,
    )
    subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=str(repo), check=True, capture_output=True,
    )
    return repo


@requires_tools
def test_sanitize_exits_zero(tmp_path, sample_repo_git):
    """Full sanitize pipeline should exit 0 on the sample repo."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    exit_code = run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    assert exit_code == 0, "sanitize should exit 0 when all gates pass"


@requires_tools
def test_forbidden_files_deleted(tmp_path, sample_repo_git):
    """config.prod.yaml, .mailmap, CODEOWNERS must not exist in work tree after redact."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    assert not (work / "config.prod.yaml").exists(), "config.prod.yaml should be deleted"
    assert not (work / ".mailmap").exists(), ".mailmap should be deleted"
    assert not (work / "CODEOWNERS").exists(), "CODEOWNERS should be deleted"


@requires_tools
def test_example_file_kept(tmp_path, sample_repo_git):
    """settings.py.example has allowed suffix — must survive, but be scanned."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    assert (work / "settings.py.example").exists(), "settings.py.example should be kept"


@requires_tools
def test_post_scan_no_critical_high(tmp_path, sample_repo_git):
    """scan_report_post.json must contain no CRITICAL or HIGH findings."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    report_path = out_dir / "artifacts" / "scan_report_post.json"
    assert report_path.exists()
    findings = json.loads(report_path.read_text())
    critical_high = [
        f for f in findings if f["severity"] in ("CRITICAL", "HIGH")
    ]
    assert not critical_high, (
        f"Post-scan should have no CRITICAL/HIGH findings, got: {critical_high}"
    )


@requires_tools
def test_bundle_created_and_valid(tmp_path, sample_repo_git):
    """sanitized.bundle must exist and be cloneable."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    bundle = out_dir / "output" / "sanitized.bundle"
    assert bundle.exists(), "sanitized.bundle must be created"

    clone_dir = tmp_path / "clone"
    result = subprocess.run(
        ["git", "clone", str(bundle), str(clone_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git clone failed: {result.stderr}"
    assert clone_dir.exists()


@requires_tools
def test_bundle_sha256_in_result(tmp_path, sample_repo_git):
    """result.json must contain bundle_sha256."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    result_path = out_dir / "artifacts" / "result.json"
    assert result_path.exists()
    doc = json.loads(result_path.read_text())
    assert "bundle_sha256" in doc
    assert len(doc["bundle_sha256"]) == 64  # SHA-256 hex


@requires_tools
def test_determinism(tmp_path, sample_repo_git):
    """Two runs with same salt produce identical bundles."""
    from repo_sanitizer.pipeline import run_sanitize

    # Run 1
    out1 = tmp_path / "out1"
    run_sanitize(
        source=str(sample_repo_git),
        out_dir=out1,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )

    # Run 2 — need a fresh copy of the source
    sample_repo2 = tmp_path / "sample_repo2"
    shutil.copytree(sample_repo_git, sample_repo2)

    out2 = tmp_path / "out2"
    run_sanitize(
        source=str(sample_repo2),
        out_dir=out2,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )

    sha1 = json.loads((out1 / "artifacts" / "result.json").read_text())["bundle_sha256"]
    sha2 = json.loads((out2 / "artifacts" / "result.json").read_text())["bundle_sha256"]
    assert sha1 == sha2, "Two runs with same salt must produce identical bundles"
