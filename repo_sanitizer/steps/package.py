from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.steps._git_utils import materialize_local_branches

logger = logging.getLogger(__name__)


def run_package(ctx: RunContext) -> Path:
    """Create a git bundle from the sanitized repository."""
    output_dir = ctx.out_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "sanitized.bundle"

    # Ensure every origin/* branch is represented as a local refs/heads/*
    # so the bundle advertises full branch topology, not only remotes.
    materialize_local_branches(ctx.work_dir)

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
        ["git", "bundle", "create", str(bundle_path), "--all"],
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

    logger.info("Bundle created: %s (SHA-256: %s)", bundle_path, sha256)
    return bundle_path
