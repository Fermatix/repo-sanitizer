from __future__ import annotations

import json
import logging
import mimetypes
from fnmatch import fnmatch
from pathlib import Path

from repo_sanitizer.context import FileAction, FileCategory, InventoryItem, RunContext
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)

CODE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".kt", ".scala", ".c", ".cpp", ".h", ".hpp", ".cs",
    ".go", ".rs", ".rb", ".php", ".swift", ".m", ".mm", ".r",
    ".sh", ".bash", ".zsh", ".fish", ".pl", ".pm", ".lua",
}

DOC_EXTENSIONS = {
    ".md", ".rst", ".txt", ".adoc", ".tex", ".html", ".htm",
    ".xml", ".csv", ".tsv", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg",
}


def run_inventory(ctx: RunContext) -> list[InventoryItem]:
    rulepack: Rulepack = ctx.rulepack
    work_dir = ctx.work_dir
    max_bytes = ctx.max_file_mb * 1024 * 1024

    items = []
    for file_path in _walk_files(work_dir):
        rel = str(file_path.relative_to(work_dir))
        if rel.startswith(".git/") or rel == ".git":
            continue

        size = file_path.stat().st_size
        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        category = _classify(file_path, mime)
        action, reason = _decide_action(rel, file_path, size, max_bytes, category, rulepack)

        items.append(
            InventoryItem(
                path=rel,
                size=size,
                mime=mime,
                category=category,
                action=action,
                reason=reason,
            )
        )

    ctx.inventory = items

    artifact_path = ctx.artifacts_dir / "inventory.json"
    artifact_path.write_text(
        json.dumps([i.to_dict() for i in items], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Inventory: %d files catalogued", len(items))
    return items


def _walk_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p


def _classify(file_path: Path, mime: str) -> FileCategory:
    ext = file_path.suffix.lower()
    if ext in CODE_EXTENSIONS:
        return FileCategory.CODE
    if ext in DOC_EXTENSIONS:
        return FileCategory.DOCS
    if mime.startswith("text/"):
        return FileCategory.DOCS
    if mime.startswith("image/") or mime.startswith("audio/") or mime.startswith("video/"):
        return FileCategory.BINARY
    if mime == "application/octet-stream":
        return FileCategory.BINARY
    name = file_path.name.lower()
    if name in (".env", ".mailmap", "codeowners") or ext in (".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
        return FileCategory.CONFIG
    return FileCategory.DOCS


def _decide_action(
    rel: str,
    file_path: Path,
    size: int,
    max_bytes: int,
    category: FileCategory,
    rulepack: Rulepack,
) -> tuple[FileAction, str]:
    ext = file_path.suffix.lower()
    name = file_path.name

    # Check if file has an allowed suffix first (e.g. .env.template, config.yaml.example)
    # Strip the allowed suffix to get the "base" name for deny-glob matching
    has_allow_suffix = any(rel.endswith(s) for s in rulepack.allow_suffixes)
    base_name = name
    if has_allow_suffix:
        for suffix in rulepack.allow_suffixes:
            if name.endswith(suffix):
                base_name = name[: -len(suffix)]
                break

    # Check deny_globs against both actual name and base name (sans allowed suffix)
    for glob_pat in rulepack.deny_globs:
        pat_name = glob_pat.split("/")[-1]
        if (
            fnmatch(rel, glob_pat)
            or fnmatch(name, pat_name)
            or (has_allow_suffix and fnmatch(base_name, pat_name))
        ):
            if has_allow_suffix:
                return FileAction.SCAN, f"matches deny glob '{glob_pat}' but has allowed suffix"
            return FileAction.DELETE, f"matches deny glob '{glob_pat}'"

    # Files with allowed suffixes that didn't match deny_globs are still scanned
    if has_allow_suffix:
        return FileAction.SCAN, "has allowed suffix"

    # Binary files
    if category == FileCategory.BINARY:
        ext_no_dot = ext.lstrip(".")
        if ext_no_dot in rulepack.binary_deny_extensions:
            return FileAction.DELETE, f"binary with denied extension '{ext_no_dot}'"
        if ext_no_dot in rulepack.binary_allow_extensions:
            return FileAction.SKIP, f"binary with allowed extension '{ext_no_dot}'"
        return FileAction.SKIP, "binary file"

    # Size limit
    if size > max_bytes:
        logger.warning("File %s exceeds size limit (%d > %d bytes)", rel, size, max_bytes)
        return FileAction.SKIP, f"exceeds max_file_mb ({size} bytes)"

    return FileAction.SCAN, ""
