from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path

from repo_sanitizer.context import RunContext

logger = logging.getLogger(__name__)

# Paths listed per bucket in artifacts/working_tree_delta.json; the counts are always complete.
_DELTA_PATH_CAP = 500


class EmptyRepositoryError(RuntimeError):
    """Raised when the repository has no commits and a bundle cannot be created."""


def working_tree_delta(work_dir: Path) -> dict:
    """Paths where the index / working tree differ from HEAD — measured, never changed.

    One ``git status --porcelain=v1 -z -uall`` over the sanitized clone. The history
    rewrite (git-filter-repo) already ``reset --hard``s the working tree to the rewritten
    HEAD, so whatever still differs was never part of the rewritten history: untracked
    files (``.DS_Store``), NFC/NFD or case duplicates of a path on a case-insensitive
    filesystem, a stale leftover of the working-tree redaction pass. The delivered history
    is the partner's rewritten history only, so this delta is reported as a residual and
    NEVER committed (see ``run_package``).

    Returns ``{"modified": [...], "untracked": [...], "error": str | None}`` with paths
    relative to ``work_dir``. ``modified`` covers every tracked-side status (index and/or
    working tree: M/A/D/R/C/T/U); ``untracked`` is ``??``.
    """
    r = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "-uall"],
        cwd=str(work_dir),
        capture_output=True,
    )
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip()
        logger.warning("git status failed while measuring the working-tree delta: %s", err)
        return {"modified": [], "untracked": [], "error": err or f"git status exit {r.returncode}"}

    modified: list[str] = []
    untracked: list[str] = []
    fields = r.stdout.split(b"\0")
    i = 0
    while i < len(fields):
        entry = fields[i]
        i += 1
        if not entry:
            continue
        xy, path = entry[:2], entry[3:].decode("utf-8", "replace")
        if xy == b"??":
            untracked.append(path)
            continue
        modified.append(path)
        if xy[:1] in (b"R", b"C"):
            # a staged rename/copy carries its source path as the next NUL-separated field
            i += 1
    return {"modified": modified, "untracked": untracked, "error": None}


def run_package(ctx: RunContext) -> Path:
    """Create a git bundle from the sanitized repository.

    This step NEVER creates a commit. The shipped history is the partner's rewritten
    history and nothing else — no "Sanitized by repo-sanitizer" tip, no empty commit, no
    working-tree snapshot appended on top of a branch (the same rule as for restoration
    commits: nothing the pipeline did may appear as a commit on top of the partner
    history, user decision 2026-09-18). Until then this step ran ``git add -A`` and
    committed the working-tree-vs-HEAD delta (``--allow-empty``); the nine part-9 tips
    built that way carried nothing their parent lacked and had to be dropped by hand.
    The delta is measured and reported instead (``working_tree_delta``); anything the
    working-tree pass redacted that the history rewrite did not is a finding to fix in
    the rewrite, never a commit.
    """
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

    # Residual: working tree / index vs HEAD. Reported, left untouched, NOT shipped —
    # the bundle below is built from refs only, so the working tree cannot leak into it.
    delta = working_tree_delta(ctx.work_dir)
    n_modified, n_untracked = len(delta["modified"]), len(delta["untracked"])
    delta_doc = {
        "modified": n_modified,
        "untracked": n_untracked,
        "committed": False,
        "shipped": False,
        "note": (
            "index/working tree differ from HEAD after the history rewrite; left as is and never "
            "committed — the bundle carries the rewritten history only. A redaction that exists "
            "only here is a gap in the history rewrite, not something to commit."
        ),
        "error": delta["error"],
        "modified_paths": delta["modified"][:_DELTA_PATH_CAP],
        "untracked_paths": delta["untracked"][:_DELTA_PATH_CAP],
    }
    delta_path = ctx.artifacts_dir / "working_tree_delta.json"
    delta_path.write_text(json.dumps(delta_doc, indent=2, ensure_ascii=False), encoding="utf-8")
    if n_modified or n_untracked:
        logger.warning(
            "Residual: working tree differs from HEAD (%d modified, %d untracked) — left uncommitted, "
            "NOT shipped; paths in %s",
            n_modified, n_untracked, delta_path,
        )

    result = subprocess.run(
        # `--`: with a top-level `head/` path in the tree, HEAD is "both revision and filename" on a case-insensitive
        # filesystem and git aborts the bundle (fa257c23, APFS)
        ["git", "bundle", "create", str(bundle_path), "--branches", "HEAD", "--"],
        cwd=str(ctx.work_dir),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"git bundle create failed: {result.stderr}")

    sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()

    result_path = ctx.artifacts_dir / "result.json"
    if result_path.exists():
        doc = json.loads(result_path.read_text(encoding="utf-8"))
    else:
        doc = {}
    doc["bundle_sha256"] = sha256
    doc["bundle_path"] = str(bundle_path)
    doc["working_tree_delta"] = {
        "modified": n_modified,
        "untracked": n_untracked,
        "committed": False,
        "artifact": str(delta_path),
    }
    result_path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    size_mb = bundle_path.stat().st_size / (1024 * 1024)
    logger.info("Bundle: %s (%.1f MB · SHA: %s)", bundle_path.name, size_mb, sha256[:12])
    return bundle_path
