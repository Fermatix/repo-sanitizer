from __future__ import annotations

import subprocess
from pathlib import Path


def materialize_local_branches(repo_dir: Path) -> None:
    """Create local refs/heads/* for each remote-tracking origin/* branch."""
    refs = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    for remote_ref in refs.stdout.splitlines():
        remote_ref = remote_ref.strip()
        if not remote_ref or remote_ref == "origin/HEAD":
            continue
        branch_name = remote_ref.removeprefix("origin/")
        exists = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"],
            cwd=str(repo_dir),
            capture_output=True,
        )
        if exists.returncode == 0:
            continue
        subprocess.run(
            ["git", "branch", "--track", branch_name, remote_ref],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )
