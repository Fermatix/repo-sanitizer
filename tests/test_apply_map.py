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
def brand_repo_path(tmp_path) -> Path:
    script = FIXTURES_DIR / "create_brand_history_repo.sh"
    dest = tmp_path / "brand_repo"
    subprocess.run(["bash", str(script), str(dest)], check=True, capture_output=True, text=True)
    return dest


def _log_all(work: Path) -> str:
    return subprocess.run(
        ["git", "log", "--all", "-p"], cwd=str(work), capture_output=True, text=True
    ).stdout


@requires_tools
def test_secret_only_in_history_is_scrubbed(tmp_path, brand_repo_path):
    """A token that exists only in an old commit's blob must be gone after Pass-1
    (full-history gitleaks collection → secret-literal scrub in blob_callback)."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(brand_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
        ner_scope="off",
    )
    work = out_dir / "work"
    log = _log_all(work)
    assert "Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk" not in log


@requires_tools
def test_commit_message_only_secret_scrubbed(tmp_path, brand_repo_path):
    """A gitleaks-detectable secret living ONLY in a commit message (which native
    gitleaks does not scan) must still be collected (message-text pass) and
    scrubbed — and the fail-closed gate must agree the history is clean."""
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    rc = run_sanitize(
        source=str(brand_repo_path),
        out_dir=out_dir,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
        ner_scope="off",
    )
    work = out_dir / "work"
    messages = subprocess.run(
        ["git", "log", "--all", "--format=%B"], cwd=str(work), capture_output=True, text=True
    ).stdout
    assert "Qm9Wd3Lp7Tk2Rs8Yv4Xb1Nc6Hd0Jf5Gg" not in messages
    # gate is fail-closed on surviving history secrets → a clean run exits 0
    assert rc == 0


def _has_git() -> bool:
    return shutil.which("git") is not None


@pytest.mark.skipif(not _has_git(), reason="git not installed")
def test_verify_brand_map_detects_survivor(tmp_path):
    """verify_brand_map_applied flags a brand that is still present in history
    (here the rewrite was NOT run), so apply-map cannot report success blindly."""
    import types
    from repo_sanitizer.steps.history_rewrite import verify_brand_map_applied

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "a@b.co"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    (repo / "f.py").write_text("client = 'Extyl'\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "init"], cwd=repo, check=True)

    ctx = types.SimpleNamespace(work_dir=repo)
    rows = [{"pattern": r"(?i)extyl", "replacement": "acme1", "is_regex": True}]
    survivors = verify_brand_map_applied(ctx, rows)
    assert survivors, "verify must flag the un-rewritten brand"


@pytest.mark.skipif(not _has_git(), reason="git not installed")
def test_verify_brand_map_shared_blob_path(tmp_path):
    """A brand path sharing a blob with a clean path must still be flagged — the
    path scan must not be deduped by blob SHA."""
    import types
    from repo_sanitizer.steps.history_rewrite import verify_brand_map_applied

    repo = tmp_path / "repo"
    (repo / "aaa" / "acme1").mkdir(parents=True)
    (repo / "zzz" / "extyl").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "a@b.co"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    # identical content → identical blob SHA under two different paths
    (repo / "aaa" / "acme1" / "same.txt").write_text("nothing sensitive here\n")
    (repo / "zzz" / "extyl" / "same.txt").write_text("nothing sensitive here\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "init"], cwd=repo, check=True)

    ctx = types.SimpleNamespace(work_dir=repo)
    rows = [{"pattern": r"(?i)extyl", "replacement": "acme1", "is_regex": True}]
    survivors = verify_brand_map_applied(ctx, rows)
    assert any("extyl" in s for s in survivors), (
        "brand in a path sharing a blob with a clean path must still be flagged"
    )


@requires_tools
def test_gitleaks_allow_comment_does_not_suppress(tmp_path):
    """A secret annotated with `# gitleaks:allow` must NOT slip past — every
    gitleaks pass uses --ignore-gitleaks-allow."""
    import os
    src = tmp_path / "repo"
    src.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=src, check=True)
    subprocess.run(["git", "config", "user.email", "a@b.co"], cwd=src, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=src, check=True)
    (src / "app.py").write_text(
        'KEY = "Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk"  # gitleaks:allow\nprint(1)\n'
    )
    subprocess.run(["git", "add", "-A"], cwd=src, check=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-qm", "init"], cwd=src, check=True
    )
    from repo_sanitizer.pipeline import run_sanitize

    out_dir = tmp_path / "out"
    run_sanitize(
        source=str(src), out_dir=out_dir, rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT", ner_scope="off",
    )
    assert "Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk" not in _log_all(out_dir / "work")


@requires_tools
def test_pass1_leaves_brands_then_apply_map_removes_them(tmp_path, brand_repo_path):
    """Pass-1 leaves brands (detection-only worklist); apply-map (Pass-3) removes
    the brand from every blob, message, AND path across all history."""
    from repo_sanitizer.pipeline import run_apply_map, run_sanitize

    # Pass-1
    out1 = tmp_path / "out1"
    run_sanitize(
        source=str(brand_repo_path),
        out_dir=out1,
        rulepack_path=RULES_DIR,
        salt_env="REPO_SANITIZER_SALT",
        ner_scope="off",
    )
    work1 = out1 / "work"
    assert "extyl" in _log_all(work1).lower(), "Pass-1 must NOT scrub brands"

    # Pass-3: apply a tiny tiered brand map over the Pass-1 output
    brand_map = tmp_path / "map.json"
    brand_map.write_text(
        json.dumps([{"pattern": r"(?i)extyl", "replacement": "acme1", "is_regex": True}])
    )
    out2 = tmp_path / "out2"
    rc = run_apply_map(
        source=str(work1),
        out_dir=out2,
        brand_map_path=brand_map,
        salt_env="REPO_SANITIZER_SALT",
    )
    assert rc == 0

    work2 = out2 / "work"
    log2 = _log_all(work2).lower()
    assert "extyl" not in log2, "apply-map must remove the brand from all history"
    assert "acme1" in log2

    # the produced bundle is cloneable and its checked-out tree shows the rename
    bundle = out2 / "output" / "sanitized.bundle"
    assert bundle.exists()
    clone = tmp_path / "clone"
    r = subprocess.run(["git", "clone", str(bundle), str(clone)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=str(clone), capture_output=True, text=True
    ).stdout
    assert "app/extyl/" not in tracked
    assert "app/acme1/" in tracked
