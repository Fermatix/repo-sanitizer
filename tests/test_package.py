from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps._git_utils import materialize_local_branches
from repo_sanitizer.steps.package import run_package, working_tree_delta


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


def _heads(repo: Path) -> dict[str, str]:
    out = _run(["git", "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads"], repo).stdout
    return dict(line.split() for line in out.splitlines() if line.strip())


def _rev_list_all(repo: Path) -> set[str]:
    return {l.strip() for l in _run(["git", "rev-list", "--all"], repo).stdout.splitlines() if l.strip()}


def _prepare_work_dir(tmp_path: Path, rules_path: Path) -> RunContext:
    source_repo = tmp_path / "source"
    _create_source_repo(source_repo)
    ctx = RunContext.create(
        source=str(source_repo),
        out_dir=tmp_path / "out",
        rulepack_path=rules_path,
        salt_env="REPO_SANITIZER_SALT",
    )
    # Reproduce common state after clone: local main, remote origin/dev exists.
    _run(["git", "clone", str(source_repo), str(ctx.work_dir)], tmp_path)
    _run(["git", "config", "user.name", "Test Author"], ctx.work_dir)
    _run(["git", "config", "user.email", "test@example.com"], ctx.work_dir)
    return ctx


def test_package_includes_all_branch_refs_and_commits(tmp_path: Path, rules_path: Path):
    ctx = _prepare_work_dir(tmp_path, rules_path)
    source_repo = tmp_path / "source"
    heads_before = _run(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        ctx.work_dir,
    ).stdout.splitlines()
    assert "main" in heads_before
    assert "dev" not in heads_before

    # New contract: branch materialization is fetch's / ref-reconcile's job, NOT
    # package's. package bundles the LOCAL heads + HEAD only (never --all, which
    # would re-include tags + remote-tracking refs). Mirror what fetch does, then
    # add a tag to prove package does NOT ship it.
    materialize_local_branches(ctx.work_dir)
    _run(["git", "tag", "v1.0"], ctx.work_dir)
    heads = _heads(ctx.work_dir)

    bundle_path = run_package(ctx)
    assert bundle_path.exists()

    bundle_heads = _run(["git", "bundle", "list-heads", str(bundle_path)], tmp_path).stdout
    assert "refs/heads/main" in bundle_heads
    assert "refs/heads/dev" in bundle_heads
    # No tags, no remote-tracking refs ship in the bundle.
    assert "refs/tags/" not in bundle_heads
    assert "refs/remotes/" not in bundle_heads
    # The bundled tips are exactly the pre-package tips: package appends nothing.
    assert _heads(ctx.work_dir) == heads
    for name, sha in heads.items():
        assert f"{sha} refs/heads/{name}" in bundle_heads

    clone_dir = tmp_path / "clone"
    _run(["git", "clone", str(bundle_path), str(clone_dir)], tmp_path)
    assert _rev_list_all(clone_dir) == _rev_list_all(source_repo)

    result_doc = json.loads((ctx.artifacts_dir / "result.json").read_text())
    assert result_doc["bundle_path"] == str(bundle_path)
    assert len(result_doc["bundle_sha256"]) == 64
    assert result_doc["working_tree_delta"] == {
        "modified": 0, "untracked": 0, "committed": False,
        "artifact": str(ctx.artifacts_dir / "working_tree_delta.json"),
    }


def test_package_never_commits_the_working_tree_delta(tmp_path: Path, rules_path: Path):
    """A delivered repo must carry no pipeline commit on top of the partner history
    (user rule 2026-09-18). Until then package ran `git add -A` + commit
    "Sanitized by repo-sanitizer" (--allow-empty) whenever the working tree differed
    from the rewritten HEAD — .DS_Store files, NFC/NFD duplicates, stale working-tree
    redactions. Now the delta is measured, reported as a residual and left alone."""
    ctx = _prepare_work_dir(tmp_path, rules_path)
    materialize_local_branches(ctx.work_dir)
    work = ctx.work_dir

    # Dirty the working tree in every way the old step would have committed:
    (work / "base.txt").write_text("redacted-only-in-working-tree\n", encoding="utf-8")  # tracked, modified
    (work / "staged.txt").write_text("staged\n", encoding="utf-8")
    _run(["git", "add", "staged.txt"], work)                                              # staged addition
    _run(["git", "mv", "main.txt", "renamed.txt"], work)                                  # staged rename (2 status fields)
    (work / ".DS_Store").write_bytes(b"\x00Bud1")                                         # untracked noise
    (work / "sub").mkdir()
    (work / "sub" / "untracked.txt").write_text("x\n", encoding="utf-8")                  # untracked in a new dir

    heads_before = _heads(work)
    commits_before = _rev_list_all(work)
    status_before = _run(["git", "status", "--porcelain=v1", "-uall"], work).stdout

    bundle_path = run_package(ctx)

    # 1. No commit was created anywhere: same tips, same commit set, no sanitizer identity.
    assert _heads(work) == heads_before
    assert _rev_list_all(work) == commits_before
    log = _run(["git", "log", "--all", "--format=%ae %s"], work).stdout
    assert "sanitizer@example.invalid" not in log
    assert "Sanitized by repo-sanitizer" not in log

    # 2. The working tree and index were left exactly as they were (no reset/clean/add).
    assert _run(["git", "status", "--porcelain=v1", "-uall"], work).stdout == status_before
    assert (work / "base.txt").read_text(encoding="utf-8") == "redacted-only-in-working-tree\n"
    assert (work / ".DS_Store").exists()

    # 3. The bundle carries the pre-package tips only; the delta does not ship.
    bundle_heads = _run(["git", "bundle", "list-heads", str(bundle_path)], tmp_path).stdout
    for name, sha in heads_before.items():
        assert f"{sha} refs/heads/{name}" in bundle_heads
    clone_dir = tmp_path / "clone"
    _run(["git", "clone", str(bundle_path), str(clone_dir)], tmp_path)
    assert _rev_list_all(clone_dir) == commits_before
    assert (clone_dir / "base.txt").read_text(encoding="utf-8") == "base\n"
    assert (clone_dir / "main.txt").exists()
    for noise in ("staged.txt", "renamed.txt", ".DS_Store", "sub"):
        assert not (clone_dir / noise).exists(), noise

    # 4. The delta is reported as a residual: counts in result.json, paths in the artifact.
    result_doc = json.loads((ctx.artifacts_dir / "result.json").read_text(encoding="utf-8"))
    delta_path = ctx.artifacts_dir / "working_tree_delta.json"
    assert result_doc["working_tree_delta"] == {
        "modified": 3, "untracked": 2, "committed": False, "artifact": str(delta_path),
    }
    delta_doc = json.loads(delta_path.read_text(encoding="utf-8"))
    assert delta_doc["committed"] is False and delta_doc["shipped"] is False
    assert delta_doc["error"] is None
    assert set(delta_doc["modified_paths"]) == {"base.txt", "staged.txt", "renamed.txt"}
    assert set(delta_doc["untracked_paths"]) == {".DS_Store", "sub/untracked.txt"}


def test_working_tree_delta_parses_rename_source_field(tmp_path: Path):
    """`git status -z` emits a staged rename as two NUL-separated fields
    (`R  new\\0old\\0`); the source path must not be counted as a second entry."""
    repo = tmp_path / "repo"
    _create_source_repo(repo)
    _run(["git", "mv", "base.txt", "moved.txt"], repo)
    (repo / "extra.txt").write_text("e\n", encoding="utf-8")
    delta = working_tree_delta(repo)
    assert delta == {"modified": ["moved.txt"], "untracked": ["extra.txt"], "error": None}


def test_working_tree_delta_clean_tree(tmp_path: Path):
    repo = tmp_path / "repo"
    _create_source_repo(repo)
    assert working_tree_delta(repo) == {"modified": [], "untracked": [], "error": None}


def test_working_tree_delta_reports_git_failure(tmp_path: Path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    delta = working_tree_delta(not_a_repo)
    assert delta["modified"] == [] and delta["untracked"] == []
    assert delta["error"]
