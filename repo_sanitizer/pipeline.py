from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from repo_sanitizer.context import RunContext
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
    ctx = RunContext.create(
        source=source,
        out_dir=out_dir,
        rulepack_path=rulepack_path,
        salt_env=salt_env,
        rev=rev,
        max_file_mb=max_file_mb,
        history_since=history_since,
        history_until=history_until,
    )
    ctx.ner_service_url = ner_service_url

    rulepack = load_rulepack(ctx.rulepack_path)
    ctx.rulepack = rulepack
    if ner_device is not None:
        rulepack.ner.device = ner_device
    if max_file_mb != 20:
        ctx.max_file_mb = max_file_mb
    elif rulepack.max_file_mb:
        ctx.max_file_mb = rulepack.max_file_mb

    history_detectors = build_history_detectors(rulepack)
    ctx.timings["steps"] = {}
    t_total = time.perf_counter()

    # Step 1: Fetch
    logger.info("Step 1: Fetch")
    t0 = time.perf_counter()
    fetch(ctx, source)
    ctx.timings["steps"]["fetch"] = round(time.perf_counter() - t0, 3)

    # Step 2: Inventory
    logger.info("Step 2: Inventory")
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory"] = round(time.perf_counter() - t0, 3)

    # Step 3: Pre-scan (working tree at --rev)
    logger.info("Step 3: Pre-scan")
    detectors = build_detectors(rulepack, ner_service_url=ctx.ner_service_url)
    t0 = time.perf_counter()
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")
    ctx.timings["steps"]["scan_pre"] = round(time.perf_counter() - t0, 3)

    # Step 4: Redact
    logger.info("Step 4: Redact")
    t0 = time.perf_counter()
    run_redact(ctx, ctx.pre_findings)
    ctx.timings["steps"]["redact"] = round(time.perf_counter() - t0, 3)

    # Step 5: Post-scan (working tree)
    logger.info("Step 5: Post-scan")
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory_post"] = round(time.perf_counter() - t0, 3)
    t0 = time.perf_counter()
    ctx.post_findings = run_scan(ctx, detectors, "scan_report_post.json")
    ctx.timings["steps"]["scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 6: History pre-scan — commit metadata (all branches)
    logger.info("Step 6: History pre-scan (commit metadata, all branches)")
    t0 = time.perf_counter()
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )
    ctx.timings["steps"]["history_scan_pre"] = round(time.perf_counter() - t0, 3)

    # Step 6b: History blob pre-scan — file contents in all commits/branches
    logger.info("Step 6b: History blob pre-scan (file contents, all commits/branches)")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )
    ctx.timings["steps"]["history_blob_scan_pre"] = round(time.perf_counter() - t0, 3)

    # Step 7: History rewrite (git-filter-repo, all branches)
    logger.info("Step 7: History rewrite")
    t0 = time.perf_counter()
    run_history_rewrite(ctx)
    ctx.timings["steps"]["history_rewrite"] = round(time.perf_counter() - t0, 3)

    # Step 8: History post-scan — commit metadata
    logger.info("Step 8: History post-scan (commit metadata)")
    t0 = time.perf_counter()
    ctx.history_post_findings = run_history_scan(
        ctx, detectors, "history_scan_post.json"
    )
    ctx.timings["steps"]["history_scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 8b: History blob post-scan — verify file contents cleaned
    logger.info("Step 8b: History blob post-scan (file contents verification)")
    t0 = time.perf_counter()
    ctx.history_blob_post_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_post.json"
    )
    ctx.timings["steps"]["history_blob_scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 9: Gate check
    logger.info("Step 9: Gate check")
    t0 = time.perf_counter()
    result = run_gate_check(ctx)
    ctx.timings["steps"]["gate_check"] = round(time.perf_counter() - t0, 3)

    # Step 10: Package
    logger.info("Step 10: Package")
    t0 = time.perf_counter()
    run_package(ctx)
    ctx.timings["steps"]["package"] = round(time.perf_counter() - t0, 3)

    ctx.timings["total_s"] = round(time.perf_counter() - t_total, 3)
    _patch_result_json(ctx)

    exit_code = result.get("exit_code", 1)
    if exit_code == 0:
        logger.info("All gates passed. Bundle created successfully.")
    else:
        logger.warning("Some gates failed. Exit code: %d", exit_code)

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
    ctx = RunContext.create(
        source=source,
        out_dir=out_dir,
        rulepack_path=rulepack_path,
        salt_env=salt_env,
        rev=rev,
        max_file_mb=max_file_mb,
        history_since=history_since,
        history_until=history_until,
    )
    ctx.ner_service_url = ner_service_url

    rulepack = load_rulepack(ctx.rulepack_path)
    ctx.rulepack = rulepack
    if ner_device is not None:
        rulepack.ner.device = ner_device
    if max_file_mb != 20:
        ctx.max_file_mb = max_file_mb
    elif rulepack.max_file_mb:
        ctx.max_file_mb = rulepack.max_file_mb

    history_detectors = build_history_detectors(rulepack)
    ctx.timings["steps"] = {}
    t_total = time.perf_counter()

    # Step 1: Fetch
    logger.info("Step 1: Fetch")
    t0 = time.perf_counter()
    fetch(ctx, source)
    ctx.timings["steps"]["fetch"] = round(time.perf_counter() - t0, 3)

    # Step 2: Inventory
    logger.info("Step 2: Inventory")
    t0 = time.perf_counter()
    run_inventory(ctx)
    ctx.timings["steps"]["inventory"] = round(time.perf_counter() - t0, 3)

    # Step 3: Pre-scan (working tree)
    logger.info("Step 3: Pre-scan")
    detectors = build_detectors(rulepack, ner_service_url=ctx.ner_service_url)
    t0 = time.perf_counter()
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")
    ctx.timings["steps"]["scan_pre"] = round(time.perf_counter() - t0, 3)

    # Step 6: History scan — commit metadata (all branches)
    logger.info("Step 6: History scan (commit metadata, all branches)")
    t0 = time.perf_counter()
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )
    ctx.timings["steps"]["history_scan_pre"] = round(time.perf_counter() - t0, 3)

    # Step 6b: History blob scan — file contents (all commits/branches)
    logger.info("Step 6b: History blob scan (file contents, all commits/branches)")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )
    ctx.timings["steps"]["history_blob_scan_pre"] = round(time.perf_counter() - t0, 3)

    ctx.timings["total_s"] = round(time.perf_counter() - t_total, 3)
    _patch_result_json(ctx)

    findings_count = (
        len(ctx.pre_findings)
        + len(ctx.history_pre_findings)
        + len(ctx.history_blob_pre_findings)
    )
    logger.info("Scan complete: %d total findings", findings_count)

    return 0 if findings_count == 0 else 1


def _patch_result_json(ctx: RunContext) -> None:
    """Merge ctx.timings (with final total_s) into artifacts/result.json."""
    result_path = ctx.artifacts_dir / "result.json"
    doc = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
    doc["timings"] = ctx.timings
    result_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
