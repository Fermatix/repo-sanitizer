from __future__ import annotations

import logging
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

    rulepack = load_rulepack(ctx.rulepack_path)
    ctx.rulepack = rulepack
    if max_file_mb != 20:
        ctx.max_file_mb = max_file_mb
    elif rulepack.max_file_mb:
        ctx.max_file_mb = rulepack.max_file_mb

    history_detectors = build_history_detectors(rulepack)

    # Step 1: Fetch
    logger.info("Step 1: Fetch")
    fetch(ctx, source)

    # Step 2: Inventory
    logger.info("Step 2: Inventory")
    run_inventory(ctx)

    # Step 3: Pre-scan (working tree at --rev)
    logger.info("Step 3: Pre-scan")
    detectors = build_detectors(rulepack)
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")

    # Step 4: Redact
    logger.info("Step 4: Redact")
    run_redact(ctx, ctx.pre_findings)

    # Step 5: Post-scan (working tree)
    logger.info("Step 5: Post-scan")
    run_inventory(ctx)
    ctx.post_findings = run_scan(ctx, detectors, "scan_report_post.json")

    # Step 6: History pre-scan — commit metadata (all branches)
    logger.info("Step 6: History pre-scan (commit metadata, all branches)")
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )

    # Step 6b: History blob pre-scan — file contents in all commits/branches
    logger.info("Step 6b: History blob pre-scan (file contents, all commits/branches)")
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )

    # Step 7: History rewrite (git-filter-repo, all branches)
    logger.info("Step 7: History rewrite")
    run_history_rewrite(ctx)

    # Step 8: History post-scan — commit metadata
    logger.info("Step 8: History post-scan (commit metadata)")
    ctx.history_post_findings = run_history_scan(
        ctx, detectors, "history_scan_post.json"
    )

    # Step 8b: History blob post-scan — verify file contents cleaned
    logger.info("Step 8b: History blob post-scan (file contents verification)")
    ctx.history_blob_post_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_post.json"
    )

    # Step 9: Gate check
    logger.info("Step 9: Gate check")
    result = run_gate_check(ctx)

    # Step 10: Package
    logger.info("Step 10: Package")
    run_package(ctx)

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

    rulepack = load_rulepack(ctx.rulepack_path)
    ctx.rulepack = rulepack
    if max_file_mb != 20:
        ctx.max_file_mb = max_file_mb
    elif rulepack.max_file_mb:
        ctx.max_file_mb = rulepack.max_file_mb

    history_detectors = build_history_detectors(rulepack)

    # Step 1: Fetch
    logger.info("Step 1: Fetch")
    fetch(ctx, source)

    # Step 2: Inventory
    logger.info("Step 2: Inventory")
    run_inventory(ctx)

    # Step 3: Pre-scan (working tree)
    logger.info("Step 3: Pre-scan")
    detectors = build_detectors(rulepack)
    ctx.pre_findings = run_scan(ctx, detectors, "scan_report_pre.json")

    # Step 6: History scan — commit metadata (all branches)
    logger.info("Step 6: History scan (commit metadata, all branches)")
    ctx.history_pre_findings = run_history_scan(
        ctx, detectors, "history_scan_pre.json"
    )

    # Step 6b: History blob scan — file contents (all commits/branches)
    logger.info("Step 6b: History blob scan (file contents, all commits/branches)")
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json"
    )

    findings_count = (
        len(ctx.pre_findings)
        + len(ctx.history_pre_findings)
        + len(ctx.history_blob_pre_findings)
    )
    logger.info("Scan complete: %d total findings", findings_count)

    return 0 if findings_count == 0 else 1
