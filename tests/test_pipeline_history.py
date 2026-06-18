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
def test_commit_message_pii_scrubbed(tmp_path, history_repo_path):
    """Commit-message emails are masked to @example.invalid across all commits."""
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
        ["git", "log", "--all", "--format=%B"],
        cwd=str(work),
        capture_output=True,
        text=True,
    )
    assert "john.doe@example.com" not in result.stdout
    assert "@corp.com" not in result.stdout


@pytest.fixture
def buildfiles_repo_path(tmp_path) -> Path:
    script = FIXTURES_DIR / "create_buildfiles_repo.sh"
    dest = tmp_path / "buildfiles_repo"
    subprocess.run(
        ["bash", str(script), str(dest)], check=True, capture_output=True, text=True
    )
    return dest


@requires_tools
def test_buildfiles_survive_but_pii_masked(tmp_path, buildfiles_repo_path):
    """End-to-end Pass-1 over the shipped bundle (= Layer B / history blobs):
    build-critical infra survives verbatim, real PII + public IP + secret URL are
    masked. This is the regression guard for the audit's 10/11-don't-build cause."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(buildfiles_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
        ner_scope="off",
    )
    bundle = out_dir / "output" / "sanitized.bundle"
    assert bundle.exists()
    clone = tmp_path / "clone"
    r = subprocess.run(["git", "clone", str(bundle), str(clone)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    def _read(name: str) -> str:
        return (clone / name).read_text(encoding="utf-8")

    # ── KEEP: build-critical, non-identifying infrastructure ────────────────
    compose = _read("docker-compose.yml")
    assert "127.0.0.1:8080:80" in compose, "loopback host bind must survive"
    assert "192.168.1.10:5432:5432" in compose, "private host bind must survive"
    assert "9A19103F-16F7-4668-BE54-5B6A7B8C9D0E" in _read("App.sln"), ".sln GUID must survive (no uuid pattern)"
    assert "https://deb.nodesource.com/setup_18.x" in _read("Dockerfile"), "public package URL (allowlisted) must survive"
    assert "git@github.com:org/repo.git" in _read("composer.json"), "SSH git remote must survive (not an email)"
    assert "https://api.nuget.org/v3/index.json" in _read("NuGet.Config"), "public feed URL (allowlisted) must survive"
    assert "884951234567894951234567890" in _read("checksums.txt"), "digit-run hash must survive (phone boundary)"
    # composer.json must still be valid JSON after the rewrite
    json.loads(_read("composer.json"))

    # ── MASK: real PII, public IP, secret-bearing URL, company URL HOST ──────
    assert "52.14.226.9" not in compose, "public IP must be masked"
    contact = _read("CONTACT.md")
    assert "real.dev@company.com" not in contact, "real email must be masked"
    assert "+7 (495) 123-45-67" not in contact, "real phone must be masked"
    assert "liveSECRETtoken1234567890" not in contact, "secret URL token must be masked"
    # company URL host masked (REDACTED_<hash> via the secret-literal path for a
    # scanned blob, or <hash>.example.invalid via the Scrubber URL pass for an
    # unscanned one). Key point vs the old blanket https_url: only the HOST is
    # replaced — the path survives, so the line stays a structurally valid URL.
    assert "acmevendor.io" not in contact, "company URL host must be masked"
    api_line = next(ln for ln in contact.splitlines() if ln.startswith("API base:"))
    assert "https://" in api_line and api_line.endswith("/v1/orders"), (
        f"masked URL must keep scheme+path (host-only mask), got: {api_line!r}"
    )
    assert "[" not in api_line, "the host-only URL mask must not introduce a [..] token"


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
