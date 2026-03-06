from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps._git_utils import materialize_local_branches

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
    elif source_path.is_dir():
        logger.debug("Copying directory %s → %s", source, dest)
        shutil.copytree(source_path, dest)
    else:
        raise ValueError(
            f"Source '{source}' is not a valid local directory or Git URL."
        )

    if ctx.rev != "HEAD":
        subprocess.run(
            ["git", "checkout", ctx.rev],
            cwd=str(dest),
            check=True,
            capture_output=True,
            text=True,
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
