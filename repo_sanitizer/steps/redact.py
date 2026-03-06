from __future__ import annotations

import json
import logging
from pathlib import Path

from repo_sanitizer.context import FileAction, FileCategory, RunContext
from repo_sanitizer.detectors.base import Finding
from repo_sanitizer.extractors.fallback import FallbackExtractor
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor
from repo_sanitizer.redaction.applier import apply_redactions
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


def run_redact(ctx: RunContext, findings: list[Finding]) -> list[dict]:
    rulepack: Rulepack = ctx.rulepack
    ts_extractor = TreeSitterExtractor(rulepack.extractor)

    # 1. Delete files with DELETE action
    for item in ctx.inventory:
        if item.action == FileAction.DELETE:
            file_path = ctx.work_dir / item.path
            if file_path.exists():
                file_path.unlink()
                logger.debug("Deleted: %s", item.path)

    # 2. Group findings by file
    findings_by_file: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_file.setdefault(f.file_path, []).append(f)

    all_manifest: list[dict] = []

    for file_rel, file_findings in findings_by_file.items():
        file_path = ctx.work_dir / file_rel
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning("Cannot read %s for redaction: %s", file_rel, e)
            continue

        # For code files, verify findings are within zones
        item = next((i for i in ctx.inventory if i.path == file_rel), None)
        if item and item.category == FileCategory.CODE:
            zones = ts_extractor.extract_zones(file_rel, content)
            if zones is not None:
                file_findings = [
                    f
                    for f in file_findings
                    if any(
                        z.start <= f.offset_start and f.offset_end <= z.end
                        for z in zones
                    )
                ]

        if not file_findings:
            continue

        redacted, manifest = apply_redactions(content, file_findings, ctx.salt)
        file_path.write_text(redacted, encoding="utf-8")
        all_manifest.extend(manifest)
        logger.debug("Redacted %d findings in %s", len(manifest), file_rel)

    ctx.redaction_manifest = all_manifest

    artifact_path = ctx.artifacts_dir / "redaction_manifest.json"
    artifact_path.write_text(
        json.dumps(all_manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.debug("Redaction complete: %d replacements", len(all_manifest))
    return all_manifest
