from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps.package import run_package


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def _create_source_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-b", "main"], path)
    _run(["git", "config", "user.name", "Test Author"], path)
    _run(["git", "config", "user.email", "test@example.com"], path)

    (path / "base.txt").write_text("base\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "base"], path)

    _run(["git", "checkout", "-b", "dev"], path)
    (path / "dev.txt").write_text("dev\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "dev-commit"], path)

    _run(["git", "checkout", "main"], path)
    (path / "main.txt").write_text("main\n", encoding="utf-8")
    _run(["git", "add", "-A"], path)
    _run(["git", "commit", "-m", "main-commit"], path)


def test_package_includes_all_branch_refs_and_commits(tmp_path: Path, rules_path: Path):
    source_repo = tmp_path / "source"
    _create_source_repo(source_repo)

    out_dir = tmp_path / "out"
    ctx = RunContext.create(
        source=str(source_repo),
        out_dir=out_dir,
        rulepack_path=rules_path,
        salt_env="REPO_SANITIZER_SALT",
    )

    # Reproduce common state after clone: local main, remote origin/dev exists.
    _run(["git", "clone", str(source_repo), str(ctx.work_dir)], tmp_path)
    heads_before = _run(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        ctx.work_dir,
    ).stdout.splitlines()
    assert "main" in heads_before
    assert "dev" not in heads_before

    bundle_path = run_package(ctx)
    assert bundle_path.exists()

    bundle_heads = _run(["git", "bundle", "list-heads", str(bundle_path)], tmp_path).stdout
    assert "refs/heads/main" in bundle_heads
    assert "refs/heads/dev" in bundle_heads

    clone_dir = tmp_path / "clone"
    _run(["git", "clone", str(bundle_path), str(clone_dir)], tmp_path)

    source_all = {
        line.strip()
        for line in _run(["git", "rev-list", "--all"], source_repo).stdout.splitlines()
        if line.strip()
    }
    clone_all = {
        line.strip()
        for line in _run(["git", "rev-list", "--all"], clone_dir).stdout.splitlines()
        if line.strip()
    }
    assert len(clone_all) >= len(source_all)

    result_doc = json.loads((ctx.artifacts_dir / "result.json").read_text())
    assert result_doc["bundle_path"] == str(bundle_path)
    assert len(result_doc["bundle_sha256"]) == 64

