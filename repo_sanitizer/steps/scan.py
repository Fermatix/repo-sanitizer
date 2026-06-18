from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from repo_sanitizer.context import FileAction, FileCategory, RunContext
from repo_sanitizer.detectors.base import Detector, Finding, ScanTarget, Zone
from repo_sanitizer.encoding import read_text_detect
from repo_sanitizer.extractors.fallback import FallbackExtractor
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor, check_grammar_packages
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


# Dictionary keys that are NOT brand terms: the keep-list (allowlist) and the
# domains list (fed to EndpointDetector only — feeding bare hostnames like
# `mail`/`admin`/`jira` to the brand matcher floods it with substring matches).
_NON_BRAND_DICTS = ("keep", "domains")


def build_brand_terms(rulepack: Rulepack) -> tuple[list[str], set[str]]:
    """Return (variant-expanded brand terms, lowercased keep-set).

    The brand terms are every dictionary EXCEPT `keep` and `domains`, each run
    through variant expansion (separator / Cyrillic / mojibake forms), deduped,
    with any term that is itself on the keep-list dropped. Single source of
    truth shared by the literal DictionaryDetector and the structural
    path/identifier brand passes.
    """
    from repo_sanitizer.variants import expand_term

    # Variant-expand the keep-list too, so a kept term's Cyrillic / mojibake /
    # separator forms are also exempt (and so they win over a brand dictionary
    # that lists the same term in another script).
    keep: set[str] = set()
    for term in rulepack.dictionaries.get("keep", []):
        for variant in expand_term(term):
            keep.add(variant.lower())
    out: list[str] = []
    seen: set[str] = set()
    for name, terms in rulepack.dictionaries.items():
        if name in _NON_BRAND_DICTS:
            continue
        for term in terms:
            for variant in expand_term(term):
                key = variant.lower()
                if not key or key in keep or key in seen:
                    continue
                seen.add(key)
                out.append(variant)
    return out, keep


def build_detectors(rulepack: Rulepack, ner_service_url: str | None = None) -> list[Detector]:
    from repo_sanitizer.detectors.secrets import SecretsDetector
    from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
    from repo_sanitizer.detectors.dictionary import DictionaryDetector
    from repo_sanitizer.detectors.endpoint import EndpointDetector
    from repo_sanitizer.detectors.ner import NERDetector

    brand_terms, keep = build_brand_terms(rulepack)

    detectors: list[Detector] = []
    detectors.append(SecretsDetector())
    if rulepack.pii_patterns:
        detectors.append(RegexPIIDetector(rulepack.pii_patterns))
    if brand_terms:
        detectors.append(DictionaryDetector({"brands": brand_terms}, keep=keep))
    domain_list = rulepack.dictionaries.get("domains", [])
    detectors.append(EndpointDetector(domain_list, keep=keep))
    detectors.append(NERDetector(rulepack.ner, service_url=ner_service_url, keep=keep))
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
    from repo_sanitizer.detectors.brand_structural import (
        BrandMatcher,
        BrandPathDetector,
        BrandStructuralDetector,
    )

    rulepack: Rulepack = ctx.rulepack
    ts_extractor = TreeSitterExtractor(rulepack.extractor)
    fb_extractor = FallbackExtractor(rulepack.extractor.fallback_comment_patterns)

    _warn_missing_grammars(rulepack)

    # Structural brand passes (detection-only; gated, never rewritten — Pass-2
    # owns the coherent rename). Share one automaton built from the same
    # variant-expanded, keep-filtered brand terms as the literal DictionaryDetector.
    brand_terms, keep = build_brand_terms(rulepack)
    brand_matcher = BrandMatcher(brand_terms, keep)
    path_detector = BrandPathDetector(brand_matcher)
    struct_detector = BrandStructuralDetector(brand_matcher)

    all_findings: list[Finding] = []
    detector_times: dict[str, float] = {type(d).__name__: 0.0 for d in detectors}
    detector_times.setdefault("BrandStructuralDetector", 0.0)
    detector_times.setdefault("BrandPathDetector", 0.0)
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
            content, _enc = read_text_detect(file_path)
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
            t0 = time.perf_counter()
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
            finally:
                detector_times[type(detector).__name__] += time.perf_counter() - t0

        # Structural brand pass (4b): brands in code identifiers / package
        # declarations. Only over TREE-SITTER zones (real string/comment zones
        # available to exclude — never over the regex fallback, which would
        # miscategorize brands inside string literals). Under the default
        # on_parse_error=fallback a missing grammar yields the regex fallback
        # (used_fallback True) and is skipped here; the scan logs a "grammar
        # packages are not installed" warning — install them
        # (repo-sanitizer install-grammars) for full brand-in-identifier coverage.
        if (
            brand_matcher.has_terms
            and item.category == FileCategory.CODE
            and zones is not None
            and not used_fallback
        ):
            t0 = time.perf_counter()
            try:
                package_spans = ts_extractor.extract_identifier_zones(item.path, content)
                # None = second parse failed / no grammar. Normally unreachable
                # under on_parse_error=fallback (the first parse already
                # succeeded), but REACHABLE under on_parse_error=skip, where a
                # parse failure makes extract_zones return [] (so zones is not
                # None and used_fallback stays False). The guard is load-bearing
                # either way — do not remove it.
                if package_spans is not None:
                    struct_findings = struct_detector.detect(
                        item.path, content, zones, package_spans
                    )
                    for f in struct_findings:
                        f.compute_hash(ctx.salt)
                    all_findings.extend(struct_findings)
            except Exception as e:
                logger.warning("BrandStructuralDetector failed on %s: %s", item.path, e)
            finally:
                detector_times["BrandStructuralDetector"] += time.perf_counter() - t0

    # Path brand pass (4a): brands in file/dir names. Over EVERY inventory item
    # (a brand directory leaks regardless of the file's SCAN/DELETE/SKIP action).
    if brand_matcher.has_terms:
        t0 = time.perf_counter()
        path_findings = path_detector.detect_inventory(ctx.inventory)
        for f in path_findings:
            f.compute_hash(ctx.salt)
        all_findings.extend(path_findings)
        detector_times["BrandPathDetector"] += time.perf_counter() - t0

    _log_extractor_summary(ts_files, fallback_files)
    scan_key = report_name.removesuffix(".json")
    ctx.timings.setdefault("detectors", {})[scan_key] = {
        k: round(v, 3) for k, v in detector_times.items()
    }

    artifact_path = ctx.artifacts_dir / report_name
    artifact_path.write_text(
        json.dumps(
            [f.to_report() for f in all_findings],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    logger.debug("Scan '%s': %d findings", report_name, len(all_findings))
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
    logger.debug(
        "Extractor summary: tree-sitter=%d/%d files (%d%%), fallback=%d%s",
        len(ts_files),
        total,
        ts_pct,
        len(fallback_files),
        fb_summary,
    )
