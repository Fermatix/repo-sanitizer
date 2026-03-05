from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


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
def history_repo_path(tmp_path) -> Path:
    script = FIXTURES_DIR / "create_history_repo.sh"
    dest = tmp_path / "history_repo"
    subprocess.run(
        ["bash", str(script), str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


@requires_tools
def test_history_sanitize_exits_zero(tmp_path, history_repo_path):
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    exit_code = run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    assert exit_code == 0


@requires_tools
def test_env_removed_from_all_commits(tmp_path, history_repo_path):
    """After history rewrite, .env must not appear in any commit."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    result = subprocess.run(
        ["git", "log", "--all", "--full-history", "--", ".env"],
        cwd=str(work),
        capture_output=True,
        text=True,
    )
    assert ".env" not in result.stdout, ".env should not appear in any commit"


@requires_tools
def test_mailmap_removed_from_all_commits(tmp_path, history_repo_path):
    """After history rewrite, .mailmap must not appear in any commit."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    result = subprocess.run(
        ["git", "log", "--all", "--full-history", "--", ".mailmap"],
        cwd=str(work),
        capture_output=True,
        text=True,
    )
    assert ".mailmap" not in result.stdout, ".mailmap should not appear in any commit"


@requires_tools
def test_history_post_scan_no_findings(tmp_path, history_repo_path):
    """history_scan_post.json must have no findings after rewrite."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    report = out_dir / "artifacts" / "history_scan_post.json"
    assert report.exists()
    findings = json.loads(report.read_text())
    critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    assert not critical_high, f"History post-scan should have no C/H findings: {critical_high}"


@requires_tools
def test_author_identities_anonymized(tmp_path, history_repo_path):
    """All author emails in history should end with @example.invalid."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    work = out_dir / "work"
    result = subprocess.run(
        ["git", "log", "--format=%ae"],
        cwd=str(work),
        capture_output=True,
        text=True,
    )
    emails = [e.strip() for e in result.stdout.strip().split("\n") if e.strip()]
    for email in emails:
        assert email.endswith("@example.invalid"), (
            f"Author email '{email}' should end with @example.invalid"
        )


@requires_tools
def test_bundle_valid_after_history_rewrite(tmp_path, history_repo_path):
    """sanitized.bundle should be cloneable and have full history."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(history_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
    )
    bundle = out_dir / "output" / "sanitized.bundle"
    assert bundle.exists()

    clone_dir = tmp_path / "clone"
    result = subprocess.run(
        ["git", "clone", str(bundle), str(clone_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git clone failed: {result.stderr}"

    log_result = subprocess.run(
        ["git", "log", "--oneline"],
        cwd=str(clone_dir),
        capture_output=True,
        text=True,
    )
    commits = [l for l in log_result.stdout.strip().split("\n") if l.strip()]
    assert len(commits) >= 2, "Cloned repo should have at least 2 commits"
