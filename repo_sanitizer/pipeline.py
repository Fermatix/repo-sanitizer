from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from repo_sanitizer.context import FileAction, RunContext
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.fetch import fetch
from repo_sanitizer.steps.gate import run_gate_check
from repo_sanitizer.steps.history_blob_scan import build_history_detectors, run_history_blob_scan
from repo_sanitizer.steps.history_rewrite import run_history_rewrite
from repo_sanitizer.steps.history_scan import run_history_scan
from repo_sanitizer.steps.inventory import run_inventory
from repo_sanitizer.steps.package import run_package
from repo_sanitizer.steps.redact import run_redact
from repo_sanitizer.steps.scan import build_detectors, run_scan

logger = logging.getLogger(__name__)


def _finding_summary(findings: list) -> str:
    """Format findings count with per-category breakdown."""
    if not findings:
        return "0 findings"
    from collections import Counter
    from repo_sanitizer.detectors.base import Category
    counts = Counter(f.category for f in findings)
    parts = []
    for cat, label in [
        (Category.SECRET,     "secrets"),
        (Category.PII,        "PII"),
        (Category.ORG_NAME,   "org names"),
        (Category.DICTIONARY, "dict"),
        (Category.ENDPOINT,   "endpoints"),
    ]:
        if counts[cat]:
            parts.append(f"{counts[cat]} {label}")
    suffix = f" ({', '.join(parts)})" if parts else ""
    return f"{len(findings)} findings{suffix}"


def _build_context(
    source: str,
    out_dir: Path,
    rulepack_path: Path,
    salt_env: str,
    rev: str,
    max_file_mb: int,
    history_since: Optional[str],
    history_until: Optional[str],
    ner_device: Optional[str],
    ner_service_url: Optional[str],
) -> tuple[RunContext, object]:
    """Create RunContext and loaded Rulepack, applying CLI overrides."""
    ctx = RunContext.create(
        source=source,
        out_dir=out_dir,
        rulepack_path=rulepack_path,
        salt_env=salt_env,
        rev=rev,
        max_file_mb=max_file_mb,
        history_since=history_since,
        history_until=history_until,
        ner_service_url=ner_service_url,
    )
    rulepack = load_rulepack(ctx.rulepack_path)
    ctx.rulepack = rulepack
    if ner_device is not None:
        rulepack.ner.device = ner_device
    if max_file_mb != 20:
        ctx.max_file_mb = max_file_mb
    elif rulepack.max_file_mb:
        ctx.max_file_mb = rulepack.max_file_mb
    return ctx, rulepack


def run_sanitize(
    source: str,
    out_dir: Path,
    rulepack_path: Path,
    salt_env: str = "REPO_SANITIZER_SALT",
    rev: str = "HEAD",
    max_file_mb: int = 20,
    history_since: Optional[str] = None,
    history_until: Optional[str] = None,
    ner_device: Optional[str] = None,
    ner_service_url: Optional[str] = None,
) -> int:
    """Run the full sanitize pipeline. Returns exit code (0=pass, 1=fail)."""
    ctx, rulepack = _build_context(
        source, out_dir, rulepack_path, salt_env, rev, max_file_mb,
        history_since, history_until, ner_device, ner_service_url,
    )

    history_detectors = build_history_detectors(rulepack)
    ctx.timings["steps"] = {}
    t_total = time.perf_counter()

    # Step 1: Fetch
    t0 = time.perf_counter()
    fetch(ctx, source)
    ctx.timings["steps"]["fetch"] = round(time.perf_counter() - t0, 3)

    # Step 2: Inventory
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory"] = round(time.perf_counter() - t0, 3)
    scan_n = sum(1 for i in ctx.inventory if i.action == FileAction.SCAN)
    del_n  = sum(1 for i in ctx.inventory if i.action == FileAction.DELETE)
    skip_n = len(ctx.inventory) - scan_n - del_n
    logger.info("Inventory: %d files — %d to scan, %d to delete, %d skipped", len(ctx.inventory), scan_n, del_n, skip_n)

    # Step 3: Pre-scan (working tree at --rev)
    detectors = build_detectors(rulepack, ner_service_url=ctx.ner_service_url)
    logger.info("Scanning working tree (%d files)...", scan_n)
    t0 = time.perf_counter()
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["scan_pre"] = round(elapsed, 3)
    logger.info("Found %s (%.1fs)", _finding_summary(ctx.pre_findings), elapsed)

    # Step 4: Redact
    files_with_findings = len({f.file_path for f in ctx.pre_findings})
    logger.info("Redacting %s across %d files, deleting %d...", _finding_summary(ctx.pre_findings), files_with_findings, del_n)
    t0 = time.perf_counter()
    run_redact(ctx, ctx.pre_findings)
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["redact"] = round(elapsed, 3)
    logger.info("Redacted %d replacements (%.1fs)", len(ctx.redaction_manifest), elapsed)

    # Step 5: Post-scan (verification — silent)
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory_post"] = round(time.perf_counter() - t0, 3)
    t0 = time.perf_counter()
    ctx.post_findings = run_scan(ctx, detectors, "scan_report_post.json")
    ctx.timings["steps"]["scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 6: History pre-scan — commit metadata (all branches)
    logger.info("Scanning history (commit metadata)...")
    t0 = time.perf_counter()
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in commit metadata (%.1fs)", _finding_summary(ctx.history_pre_findings), elapsed)

    # Step 6b: History blob pre-scan — file contents in all commits/branches
    logger.info("Scanning history (file blobs)...")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_blob_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in historical blobs (%.1fs)", _finding_summary(ctx.history_blob_pre_findings), elapsed)

    # Step 7: History rewrite (git-filter-repo, all branches)
    logger.info("Rewriting history...")
    t0 = time.perf_counter()
    run_history_rewrite(ctx)
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_rewrite"] = round(elapsed, 3)
    logger.info("History rewritten (%.1fs)", elapsed)

    # Step 8 + 8b: History post-scans (verification — silent)
    t0 = time.perf_counter()
    ctx.history_post_findings = run_history_scan(
        ctx, detectors, "history_scan_post.json"
    )
    ctx.timings["steps"]["history_scan_post"] = round(time.perf_counter() - t0, 3)
    t0 = time.perf_counter()
    ctx.history_blob_post_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_post.json"
    )
    ctx.timings["steps"]["history_blob_scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 9: Gate check
    t0 = time.perf_counter()
    result = run_gate_check(ctx)
    ctx.timings["steps"]["gate_check"] = round(time.perf_counter() - t0, 3)

    # Step 10: Package
    t0 = time.perf_counter()
    run_package(ctx)
    ctx.timings["steps"]["package"] = round(time.perf_counter() - t0, 3)

    ctx.timings["total_s"] = round(time.perf_counter() - t_total, 3)
    _patch_result_json(ctx)

    remaining = (
        len(ctx.post_findings)
        + len(ctx.history_post_findings)
        + len(ctx.history_blob_post_findings)
    )
    exit_code = result.get("exit_code", 1)
    total_s = ctx.timings["total_s"]
    if exit_code == 0:
        logger.info(
            "Done: %s → %d remaining | %d redactions | %.1fs",
            _finding_summary(ctx.pre_findings),
            remaining,
            len(ctx.redaction_manifest),
            total_s,
        )
    else:
        logger.warning(
            "Gates failed: %d findings remain after sanitization (%.1fs)",
            remaining,
            total_s,
        )

    return exit_code


def run_scan_only(
    source: str,
    out_dir: Path,
    rulepack_path: Path,
    salt_env: str = "REPO_SANITIZER_SALT",
    rev: str = "HEAD",
    max_file_mb: int = 20,
    history_since: Optional[str] = None,
    history_until: Optional[str] = None,
    ner_device: Optional[str] = None,
    ner_service_url: Optional[str] = None,
) -> int:
    """Run scan-only pipeline (no redaction). Covers working tree + all history."""
    ctx, rulepack = _build_context(
        source, out_dir, rulepack_path, salt_env, rev, max_file_mb,
        history_since, history_until, ner_device, ner_service_url,
    )

    history_detectors = build_history_detectors(rulepack)
    ctx.timings["steps"] = {}
    t_total = time.perf_counter()

    # Step 1: Fetch
    t0 = time.perf_counter()
    fetch(ctx, source)
    ctx.timings["steps"]["fetch"] = round(time.perf_counter() - t0, 3)

    # Step 2: Inventory
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory"] = round(time.perf_counter() - t0, 3)
    scan_n = sum(1 for i in ctx.inventory if i.action == FileAction.SCAN)
    logger.info("Inventory: %d files (%d to scan)", len(ctx.inventory), scan_n)

    # Step 3: Pre-scan (working tree)
    detectors = build_detectors(rulepack, ner_service_url=ctx.ner_service_url)
    logger.info("Scanning working tree (%d files)...", scan_n)
    t0 = time.perf_counter()
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["scan_pre"] = round(elapsed, 3)
    logger.info("Found %s (%.1fs)", _finding_summary(ctx.pre_findings), elapsed)

    # Step 6: History scan — commit metadata (all branches)
    logger.info("Scanning history (commit metadata)...")
    t0 = time.perf_counter()
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in commit metadata (%.1fs)", _finding_summary(ctx.history_pre_findings), elapsed)

    # Step 6b: History blob scan — file contents (all commits/branches)
    logger.info("Scanning history (file blobs)...")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_blob_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in historical blobs (%.1fs)", _finding_summary(ctx.history_blob_pre_findings), elapsed)

    ctx.timings["total_s"] = round(time.perf_counter() - t_total, 3)
    _patch_result_json(ctx)

    all_findings = ctx.pre_findings + ctx.history_pre_findings + ctx.history_blob_pre_findings
    logger.info("Scan complete: %s (%.1fs)", _finding_summary(all_findings), ctx.timings["total_s"])

    return 0 if not all_findings else 1


def _patch_result_json(ctx: RunContext) -> None:
    """Merge ctx.timings (with final total_s) into artifacts/result.json."""
    result_path = ctx.artifacts_dir / "result.json"
    doc = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
    doc["timings"] = ctx.timings
    result_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
