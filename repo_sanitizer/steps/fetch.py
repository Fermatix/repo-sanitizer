from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps._git_utils import (
    detect_default_branch,
    ensure_valid_head_checkout,
    list_all_branch_tips,
    materialize_local_branches,
)

logger = logging.getLogger(__name__)


def fetch(ctx: RunContext, source: str) -> None:
    """Clone or copy the source repository into work_dir."""
    source_path = Path(source)
    dest = ctx.work_dir

    if dest.exists():
        shutil.rmtree(dest)

    if source_path.is_dir() and (source_path / ".git").is_dir():
        logger.debug("Cloning local repository %s → %s", source, dest)
        subprocess.run(
            [
                "git",
                "clone",
                "--no-hardlinks",
                "--no-single-branch",
                str(source_path),
                str(dest),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        _fetch_all_refs(dest)
        materialize_local_branches(dest)
    elif source.startswith("http://") or source.startswith("https://") or source.startswith("git@"):
        logger.debug("Cloning remote repository %s → %s", source, dest)
        subprocess.run(
            ["git", "clone", "--no-single-branch", source, str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
        _fetch_all_refs(dest)
        materialize_local_branches(dest)
    elif source_path.is_file():
        # A git bundle (e.g. a Pass-1 sanitized.bundle) — clone it like a repo.
        logger.debug("Cloning git bundle %s → %s", source, dest)
        subprocess.run(
            ["git", "clone", "--no-single-branch", str(source_path), str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
        _fetch_all_refs(dest)
        materialize_local_branches(dest)
    elif source_path.is_dir():
        logger.debug("Copying directory %s → %s", source, dest)
        shutil.copytree(source_path, dest)
    else:
        raise ValueError(
            f"Source '{source}' is not a valid local directory, git bundle, or Git URL."
        )

    if ctx.rev != "HEAD":
        subprocess.run(
            ["git", "checkout", ctx.rev],
            cwd=str(dest),
            check=True,
            capture_output=True,
            text=True,
        )
    elif (dest / ".git").exists():
        # Default-branch case: if the source bundle/repo has a broken or unborn
        # HEAD, the working tree is empty and the whole working-tree pass would be
        # skipped — repoint HEAD to the detected default branch so it runs.
        ensure_valid_head_checkout(dest)

    # Record the branch topology so ref-reconcile can keep ALL branches (with
    # scrubbed names) in the output bundle. Captured AFTER the optional --rev
    # checkout (a detached checkout leaves refs/heads/* untouched, so the set is
    # still correct). The plain directory-copy path (no .git) has no refs.
    if (dest / ".git").exists():
        ctx.intake_branch_tips = list_all_branch_tips(dest)
        ctx.intake_default_branch = detect_default_branch(dest)
        logger.debug(
            "Intake branches: %d (default=%r)",
            len(ctx.intake_branch_tips), ctx.intake_default_branch,
        )

    logger.debug("Source fetched to %s", dest)


def _fetch_all_refs(repo_dir: Path) -> None:
    """Fetch all branches and tags from origin regardless of clone defaults."""
    subprocess.run(
        [
            "git",
            "fetch",
            "--force",
            "--prune",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
            "+refs/tags/*:refs/tags/*",
        ],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
