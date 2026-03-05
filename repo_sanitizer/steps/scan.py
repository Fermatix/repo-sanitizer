from __future__ import annotations

import json
import logging
from pathlib import Path

from repo_sanitizer.context import FileAction, FileCategory, RunContext
from repo_sanitizer.detectors.base import Detector, Finding, ScanTarget, Zone
from repo_sanitizer.extractors.fallback import FallbackExtractor
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor, check_grammar_packages
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


def build_detectors(rulepack: Rulepack) -> list[Detector]:
    from repo_sanitizer.detectors.secrets import SecretsDetector
    from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
    from repo_sanitizer.detectors.dictionary import DictionaryDetector
    from repo_sanitizer.detectors.endpoint import EndpointDetector
    from repo_sanitizer.detectors.ner import NERDetector

    detectors: list[Detector] = []
    detectors.append(SecretsDetector())
    if rulepack.pii_patterns:
        detectors.append(RegexPIIDetector(rulepack.pii_patterns))
    if any(v for v in rulepack.dictionaries.values()):
        detectors.append(DictionaryDetector(rulepack.dictionaries))
    domain_list = rulepack.dictionaries.get("domains", [])
    detectors.append(EndpointDetector(domain_list))
    detectors.append(NERDetector(rulepack.ner))
    return detectors


def _warn_missing_grammars(rulepack: Rulepack) -> None:
    """Log warnings for grammar packages not installed; called once before scan."""
    statuses = check_grammar_packages(rulepack.extractor)
    missing = [s for s in statuses if not s.installed or s.missing_attribute]
    if not missing:
        return
    logger.warning(
        "Some grammar packages are not installed — affected files will use fallback extractor. "
        "Run: repo-sanitizer install-grammars --rulepack <path>"
    )
    for s in missing:
        if not s.installed:
            logger.warning("  ✗ %s (pip install %s)", s.language_id, s.grammar_package)
        else:
            logger.warning(
                "  ✗ %s: package '%s' installed but missing attribute '%s'",
                s.language_id,
                s.grammar_package,
                s.missing_attribute,
            )


def run_scan(
    ctx: RunContext,
    detectors: list[Detector],
    report_name: str = "scan_report_pre.json",
) -> list[Finding]:
    rulepack: Rulepack = ctx.rulepack
    ts_extractor = TreeSitterExtractor(rulepack.extractor)
    fb_extractor = FallbackExtractor(rulepack.extractor.fallback_comment_patterns)

    _warn_missing_grammars(rulepack)

    all_findings: list[Finding] = []
    # Stats: counts per extractor type for CODE files
    ts_files: list[str] = []
    fallback_files: list[str] = []

    for item in ctx.inventory:
        if item.action != FileAction.SCAN:
            continue

        file_path = ctx.work_dir / item.path
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning("Cannot read %s: %s", item.path, e)
            continue

        zones = None
        used_fallback = False
        if item.category == FileCategory.CODE:
            zones = ts_extractor.extract_zones(item.path, content)
            if zones is None and rulepack.extractor.fallback_enabled:
                zones = fb_extractor.extract_zones(content)
                used_fallback = True
            if zones is not None:
                if used_fallback:
                    fallback_files.append(item.path)
                else:
                    ts_files.append(item.path)

        target = ScanTarget(
            file_path=item.path,
            content=content,
            zones=zones,
        )

        for detector in detectors:
            try:
                findings = detector.detect(target)
                for f in findings:
                    f.compute_hash(ctx.salt)
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(
                    "Detector %s failed on %s: %s",
                    type(detector).__name__,
                    item.path,
                    e,
                )

    _log_extractor_summary(ts_files, fallback_files)

    artifact_path = ctx.artifacts_dir / report_name
    artifact_path.write_text(
        json.dumps(
            [f.to_report() for f in all_findings],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    logger.info("Scan '%s': %d findings", report_name, len(all_findings))
    return all_findings


def _log_extractor_summary(ts_files: list[str], fallback_files: list[str]) -> None:
    """Log a summary table of tree-sitter vs fallback coverage."""
    total = len(ts_files) + len(fallback_files)
    if total == 0:
        return

    # Group fallback files by extension to show which languages fell back
    from collections import Counter
    from pathlib import Path as _Path

    fallback_by_ext: Counter = Counter(
        _Path(f).suffix.lower() or "(no ext)" for f in fallback_files
    )

    ts_pct = 100 * len(ts_files) // total if total else 0
    fb_summary = (
        "  Fallback extensions: "
        + ", ".join(f"{ext}×{n}" for ext, n in fallback_by_ext.most_common())
        if fallback_files
        else ""
    )
    logger.info(
        "Extractor summary: tree-sitter=%d/%d files (%d%%), fallback=%d%s",
        len(ts_files),
        total,
        ts_pct,
        len(fallback_files),
        fb_summary,
    )
