from __future__ import annotations

import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps.fetch import fetch


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def _create_multibranch_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-b", "main"], path)
    _run(["git", "config", "user.name", "Test Author"], path)
    _run(["git", "config", "user.email", "test@example.com"], path)

    (path / "base.txt").write_text("base\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "base"], path)

    _run(["git", "checkout", "-b", "feature"], path)
    (path / "feature.txt").write_text("feature\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "feature-commit"], path)
    feature_sha = _run(["git", "rev-parse", "HEAD"], path).stdout.strip()

    _run(["git", "checkout", "main"], path)
    _run(["git", "checkout", "-b", "bugfix"], path)
    (path / "bugfix.txt").write_text("bugfix\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "bugfix-commit"], path)
    _run(["git", "checkout", "main"], path)

    return feature_sha


def _local_heads(repo_dir: Path) -> set[str]:
    out = _run(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        repo_dir,
    ).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def test_fetch_materializes_all_branches(tmp_path: Path, rules_path: Path):
    source_repo = tmp_path / "source"
    _create_multibranch_repo(source_repo)

    out_dir = tmp_path / "out"
    ctx = RunContext.create(
        source=str(source_repo),
        out_dir=out_dir,
        rulepack_path=rules_path,
        salt_env="REPO_SANITIZER_SALT",
    )
    fetch(ctx, str(source_repo))

    heads = _local_heads(ctx.work_dir)
    assert {"main", "feature", "bugfix"}.issubset(heads)

    feature_log = _run(
        ["git", "log", "--format=%s", "feature", "--", "feature.txt"],
        ctx.work_dir,
    ).stdout
    bugfix_log = _run(
        ["git", "log", "--format=%s", "bugfix", "--", "bugfix.txt"],
        ctx.work_dir,
    ).stdout
    assert "feature-commit" in feature_log
    assert "bugfix-commit" in bugfix_log


def test_fetch_complex_branch_names(tmp_path: Path, rules_path: Path):
    source_repo = tmp_path / "source"
    source_repo.mkdir(parents=True)
    _run(["git", "init", "-b", "main"], source_repo)
    _run(["git", "config", "user.name", "Test"], source_repo)
    _run(["git", "config", "user.email", "t@t.com"], source_repo)
    (source_repo / "f.txt").write_text("x", encoding="utf-8")
    _run(["git", "add", "-A"], source_repo)
    _run(["git", "commit", "-m", "init"], source_repo)

    # Branch with slash (hierarchical name — common in real repos)
    _run(["git", "checkout", "-b", "feature/JIRA-42"], source_repo)
    (source_repo / "a.txt").write_text("a", encoding="utf-8")
    _run(["git", "add", "-A"], source_repo)
    _run(["git", "commit", "-m", "feat"], source_repo)
    _run(["git", "checkout", "main"], source_repo)

    # Branch with hash — git allows it locally even if some remotes reject it
    _run(["git", "checkout", "-b", "fix#99"], source_repo)
    (source_repo / "b.txt").write_text("b", encoding="utf-8")
    _run(["git", "add", "-A"], source_repo)
    _run(["git", "commit", "-m", "fix"], source_repo)
    _run(["git", "checkout", "main"], source_repo)

    out_dir = tmp_path / "out"
    ctx = RunContext.create(
        source=str(source_repo),
        out_dir=out_dir,
        rulepack_path=rules_path,
        salt_env="REPO_SANITIZER_SALT",
    )
    # Must not raise even for tricky branch names
    fetch(ctx, str(source_repo))

    heads = _local_heads(ctx.work_dir)
    assert "main" in heads
    assert "feature/JIRA-42" in heads   # slash branch must be materialized
    # fix#99: git allows it locally — must be present too
    assert "fix#99" in heads


def test_fetch_with_rev_keeps_all_branches(tmp_path: Path, rules_path: Path):
    source_repo = tmp_path / "source"
    feature_sha = _create_multibranch_repo(source_repo)

    out_dir = tmp_path / "out"
    ctx = RunContext.create(
        source=str(source_repo),
        out_dir=out_dir,
        rulepack_path=rules_path,
        salt_env="REPO_SANITIZER_SALT",
        rev=feature_sha,
    )
    fetch(ctx, str(source_repo))

    head_sha = _run(["git", "rev-parse", "HEAD"], ctx.work_dir).stdout.strip()
    assert head_sha == feature_sha

    heads = _local_heads(ctx.work_dir)
    assert {"main", "feature", "bugfix"}.issubset(heads)

