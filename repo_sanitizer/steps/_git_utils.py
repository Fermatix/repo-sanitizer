from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def materialize_local_branches(repo_dir: Path) -> None:
    """Create local refs/heads/* for each remote-tracking origin/* branch."""
    refs = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname)", "refs/remotes/origin"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    for full_ref in refs.stdout.splitlines():
        full_ref = full_ref.strip()
        if not full_ref:
            continue
        branch_name = full_ref.removeprefix("refs/remotes/origin/")
        if branch_name == full_ref or branch_name == "HEAD":
            continue
        remote_ref = f"refs/remotes/origin/{branch_name}"
        exists = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"],
            cwd=str(repo_dir),
            capture_output=True,
        )
        if exists.returncode == 0:
            continue
        result = subprocess.run(
            ["git", "branch", "--track", branch_name, remote_ref],
            cwd=str(repo_dir),
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Skipping branch %r: could not create local ref (%s)",
                branch_name,
                result.stderr.decode(errors="replace").strip(),
            )


def list_local_branch_tips(repo_dir: Path) -> dict[str, str]:
    """Return ``{branch_name: tip_sha}`` for every local ``refs/heads/*``.

    Branch names may contain ``/`` (``feature/x``); they may NOT contain spaces
    (git forbids them in ref names), so a space-delimited ``%(objectname)`` line
    is unambiguous.
    """
    r = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    tips: dict[str, str] = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        name, _, sha = line.rpartition(" ")
        if name and sha:
            tips[name] = sha
    return tips


def list_all_branch_tips(repo_dir: Path) -> dict[str, str]:
    """Return ``{branch_name: tip_sha}`` for the TRUE source branch set — every
    local ``refs/heads/*`` UNION every ``refs/remotes/origin/*`` (origin name
    stripped, ``HEAD`` symref skipped), a local head winning on name collision.

    Using the union (not just local heads) means a branch that failed to
    materialize as a local head is still recorded, so ref-reconcile recreates it
    from the rewritten tip (the rewrite's ``--all`` scope covers origin refs too)
    and BRANCHES_PRESERVED can see it — a branch is never silently lost."""
    tips = list_local_branch_tips(repo_dir)
    # FULL refname (not :short — `refs/remotes/origin/HEAD` shortens to bare
    # `origin`, which an `origin/` strip would NOT reduce to `HEAD`, leaking a
    # spurious `origin` branch). Mirrors materialize_local_branches.
    r = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname) %(objectname)", "refs/remotes/origin"],
        cwd=str(repo_dir), check=True, capture_output=True, text=True,
    )
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        full, _, sha = line.rpartition(" ")
        name = full.removeprefix("refs/remotes/origin/")
        if not name or name == full or name == "HEAD" or not sha:
            continue
        tips.setdefault(name, sha)   # local head wins
    return tips


def detect_default_branch(repo_dir: Path) -> str:
    """Best-effort default branch: ``origin/HEAD`` → current HEAD branch →
    ``main``/``master`` → first local branch → "" (none)."""
    # 1) origin/HEAD symbolic-ref (set by `git clone`)
    r = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip().removeprefix("refs/remotes/origin/")
    # 2) currently checked-out branch
    r = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=str(repo_dir), capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    # 3) main / master / first
    heads = list(list_local_branch_tips(repo_dir).keys())
    for cand in ("main", "master"):
        if cand in heads:
            return cand
    return heads[0] if heads else ""
