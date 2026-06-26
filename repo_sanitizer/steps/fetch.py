from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps._git_utils import (
    detect_default_branch,
    ensure_valid_head_checkout,
    list_all_branch_tips,
    materialize_local_branches,
)

logger = logging.getLogger(__name__)


def _run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    allow_prompt: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a git command, optionally allowing an interactive credential prompt.

    The sanitizer has no auth of its own — it clones with plain ``git``. When the
    source is an HTTPS/SSH URL whose credentials are NOT already configured
    (credential helper, token-in-URL, ssh-agent), we want git to *ask* rather
    than hang forever behind captured output. That only makes sense with a real
    terminal attached, so:

    * ``allow_prompt`` and a TTY on stdin+stderr → let git prompt
      (``GIT_TERMINAL_PROMPT=1``) and cache whatever the user types for the rest
      of this run (in-memory ``cache`` helper) so the follow-up ``git fetch``
      does not ask a second time. Output is NOT captured here — the prompt must
      reach the terminal.
    * otherwise (batch, cron, no TTY) → disable the prompt
      (``GIT_TERMINAL_PROMPT=0``) so a missing credential fails fast instead of
      blocking forever, and capture output as before.
    """
    interactive = allow_prompt and sys.stdin.isatty() and sys.stderr.isatty()
    env = dict(os.environ)
    prefix: list[str] = []
    if interactive:
        env["GIT_TERMINAL_PROMPT"] = "1"
        prefix = ["-c", "credential.helper=cache --timeout=900"]
    else:
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return subprocess.run(
        ["git", *prefix, *args],
        cwd=str(cwd) if cwd is not None else None,
        check=True,
        capture_output=not interactive,
        text=True,
        env=env,
    )


def fetch(ctx: RunContext, source: str) -> None:
    """Clone or copy the source repository into work_dir."""
    source_path = Path(source)
    dest = ctx.work_dir

    if dest.exists():
        shutil.rmtree(dest)

    if source_path.is_dir() and (source_path / ".git").is_dir():
        logger.debug("Cloning local repository %s → %s", source, dest)
        _run_git(
            ["clone", "--no-hardlinks", "--no-single-branch", str(source_path), str(dest)]
        )
        _fetch_all_refs(dest)
        materialize_local_branches(dest)
    elif source.startswith("http://") or source.startswith("https://") or source.startswith("git@"):
        logger.debug("Cloning remote repository %s → %s", source, dest)
        # Remote auth is the user's git environment (credential helper,
        # token-in-URL, ssh-agent). allow_prompt lets git ASK for HTTPS creds
        # when none are configured and a terminal is attached, instead of
        # hanging behind captured output.
        _run_git(
            ["clone", "--no-single-branch", source, str(dest)],
            allow_prompt=True,
        )
        _fetch_all_refs(dest, allow_prompt=True)
        materialize_local_branches(dest)
    elif source_path.is_file():
        # A git bundle (e.g. a Pass-1 sanitized.bundle) — clone it like a repo.
        logger.debug("Cloning git bundle %s → %s", source, dest)
        _run_git(["clone", "--no-single-branch", str(source_path), str(dest)])
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


def _fetch_all_refs(repo_dir: Path, *, allow_prompt: bool = False) -> None:
    """Fetch all branches and tags from origin regardless of clone defaults.

    ``allow_prompt`` is passed through for remote origins so this follow-up
    fetch can reuse the credentials cached during the interactive clone (and
    prompt itself if needed) instead of hanging.
    """
    _run_git(
        [
            "fetch",
            "--force",
            "--prune",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
            "+refs/tags/*:refs/tags/*",
        ],
        cwd=repo_dir,
        allow_prompt=allow_prompt,
    )
