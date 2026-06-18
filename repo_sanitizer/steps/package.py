from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext

logger = logging.getLogger(__name__)


class EmptyRepositoryError(RuntimeError):
    """Raised when the repository has no commits and a bundle cannot be created."""


def run_package(ctx: RunContext) -> Path:
    """Create a git bundle from the sanitized repository."""
    output_dir = ctx.out_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "sanitized.bundle"

    # The ref set is owned by ref-reconcile (steps/ref_reconcile.py), which ran
    # before this step: it keeps every branch under refs/heads/* (scrubbed names)
    # and deleted all tags / remotes / replace refs. So we bundle by branches +
    # HEAD only — NOT --all, which would re-include tags and remote-tracking refs.

    # Detect empty repository (no commits) before attempting to bundle.
    check = subprocess.run(
        ["git", "rev-list", "--max-count=1", "--all"],
        cwd=str(ctx.work_dir),
        capture_output=True,
        text=True,
    )
    if not check.stdout.strip():
        raise EmptyRepositoryError(
            f"Repository at {ctx.work_dir} has no commits; skipping bundle."
        )

    # Commit any pending changes
    subprocess.run(
        ["git", "add", "-A"],
        cwd=str(ctx.work_dir),
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(ctx.work_dir),
        capture_output=True,
    )
    if result.returncode != 0:
        subprocess.run(
            [
                "git",
                "-c", "user.name=sanitizer",
                "-c", "user.email=sanitizer@example.invalid",
                "commit",
                "-m",
                "Sanitized by repo-sanitizer",
                "--allow-empty",
            ],
            cwd=str(ctx.work_dir),
            capture_output=True,
            text=True,
        )

    result = subprocess.run(
        ["git", "bundle", "create", str(bundle_path), "--branches", "HEAD"],
        cwd=str(ctx.work_dir),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"git bundle create failed: {result.stderr}")

    sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()

    result_path = ctx.artifacts_dir / "result.json"
    if result_path.exists():
        doc = json.loads(result_path.read_text())
    else:
        doc = {}
    doc["bundle_sha256"] = sha256
    doc["bundle_path"] = str(bundle_path)
    result_path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    size_mb = bundle_path.stat().st_size / (1024 * 1024)
    logger.info("Bundle: %s (%.1f MB · SHA: %s)", bundle_path.name, size_mb, sha256[:12])
    return bundle_path
