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
