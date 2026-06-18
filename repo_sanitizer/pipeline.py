from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from repo_sanitizer.context import FileAction, RunContext
from repo_sanitizer.detectors.ner import NERDetector
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.fetch import fetch
from repo_sanitizer.steps.gate import run_gate_check
from repo_sanitizer.steps.history_blob_scan import build_history_detectors, run_history_blob_scan
from repo_sanitizer.steps.history_rewrite import run_history_rewrite, run_history_secret_gate
from repo_sanitizer.steps.history_scan import run_history_scan
from repo_sanitizer.steps.inventory import run_inventory
from repo_sanitizer.steps.package import run_package
from repo_sanitizer.steps.redact import run_redact
from repo_sanitizer.steps.ref_reconcile import run_ref_reconcile
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
        (Category.SECRET,            "secrets"),
        (Category.PII,               "PII"),
        (Category.ORG_NAME,          "org names"),
        (Category.DICTIONARY,        "dict"),
        (Category.ENDPOINT,          "endpoints"),
        (Category.BRAND_IDENTIFIER,  "brand idents"),
        (Category.BRAND_PATH,        "brand paths"),
        (Category.PACKAGE_NAMESPACE, "pkg/namespace"),
    ]:
        if counts[cat]:
            parts.append(f"{counts[cat]} {label}")
    suffix = f" ({', '.join(parts)})" if parts else ""
    return f"{len(findings)} findings{suffix}"


def _check_ner_service(url: str) -> None:
    """Verify the NER service is reachable and ready before starting the pipeline."""
    try:
        import httpx
        resp = httpx.get(f"{url}/health", timeout=5.0)
        status = resp.json().get("status")
        if status != "ready":
            raise RuntimeError(
                f"NER service at {url} responded but is not ready (status={status!r}). "
                "Wait for the model to finish loading."
            )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            f"NER service at {url} is unreachable: {exc}\n"
            f"Start it with: repo-sanitizer ner-service --port <PORT>"
        ) from exc


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
    ner_scope: str = "head",
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
        ner_scope=ner_scope,
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
    ner_scope: str = "head",
) -> int:
    """Run the full sanitize pipeline. Returns exit code (0=pass, 1=fail)."""
    if ner_service_url:
        _check_ner_service(ner_service_url)

    ctx, rulepack = _build_context(
        source, out_dir, rulepack_path, salt_env, rev, max_file_mb,
        history_since, history_until, ner_device, ner_service_url, ner_scope,
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
    detectors = build_detectors(
        rulepack, ner_service_url=ctx.ner_service_url, ner_scope=ctx.ner_scope
    )
    ner_detector = next((d for d in detectors if isinstance(d, NERDetector)), None)
    # NER over history (commit metadata + every blob) is the expensive 15-40h path;
    # run it ONLY under --ner-scope all. Default "head" scans NER on the working tree
    # only; "off" has no NER detector at all. Commit-metadata authors are blanket
    # anonymized regardless, so metadata-NER adds little outside "all".
    metadata_detectors = detectors if ctx.ner_scope == "all" else history_detectors
    history_ner = ner_detector if ctx.ner_scope == "all" else None
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

    # Step 5b: Converge gitleaks/regex cascades. Masking the first high-entropy
    # token often makes a NEW one the top match on re-scan; re-redact residuals
    # (working tree) until stable (≤3 passes). Brand worklist findings are
    # detection-only — they never redact, so exclude them from the convergence
    # signal or the loop would spin on them forever.
    t0 = time.perf_counter()
    _converge_redaction(ctx, detectors, max_passes=3)
    ctx.timings["steps"]["redact_converge"] = round(time.perf_counter() - t0, 3)

    # Step 6: History pre-scan — commit metadata (all branches)
    logger.info("Scanning history (commit metadata)...")
    t0 = time.perf_counter()
    ctx.history_pre_findings = run_history_scan(
        ctx, metadata_detectors, "history_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in commit metadata (%.1fs)", _finding_summary(ctx.history_pre_findings), elapsed)

    # Step 6b: History blob pre-scan — file contents in all commits/branches
    logger.info("Scanning history (file blobs)...")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json", ner_detector=history_ner
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

    # Step 7b: Reconcile refs — keep ALL branches (best-effort scrubbed names),
    # drop tags/remotes/replace, set HEAD. Runs BEFORE the post-scans so the
    # verification + secret gate certify exactly the shipped ref set (heads only),
    # not content in tags/remotes that will not ship.
    t0 = time.perf_counter()
    run_ref_reconcile(ctx)
    ctx.timings["steps"]["ref_reconcile"] = round(time.perf_counter() - t0, 3)

    # Step 8 + 8b: History post-scans (verification — silent)
    t0 = time.perf_counter()
    ctx.history_post_findings = run_history_scan(
        ctx, metadata_detectors, "history_scan_post.json"
    )
    ctx.timings["steps"]["history_scan_post"] = round(time.perf_counter() - t0, 3)
    t0 = time.perf_counter()
    ctx.history_blob_post_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_post.json", ner_detector=history_ner
    )
    ctx.timings["steps"]["history_blob_scan_post"] = round(time.perf_counter() - t0, 3)

    # Step 8c: FAIL-CLOSED full-history secret gate over the REWRITTEN repo.
    # Backstops every way secret-literal collection could miss a value
    # (message-only, <5 chars, repo-config-allowlisted, non-utf8, gitleaks FN on
    # the pre-rewrite shape). Any survivor is a SECRET finding → SECRETS gate red.
    t0 = time.perf_counter()
    secret_survivors = run_history_secret_gate(ctx)
    if secret_survivors:
        logger.warning("Post-rewrite history secret gate: %d secret(s) survive in history", len(secret_survivors))
    ctx.history_blob_post_findings = ctx.history_blob_post_findings + secret_survivors
    ctx.timings["steps"]["history_secret_gate"] = round(time.perf_counter() - t0, 3)

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
    ner_scope: str = "head",
) -> int:
    """Run scan-only pipeline (no redaction). Covers working tree + all history."""
    if ner_service_url:
        _check_ner_service(ner_service_url)

    ctx, rulepack = _build_context(
        source, out_dir, rulepack_path, salt_env, rev, max_file_mb,
        history_since, history_until, ner_device, ner_service_url, ner_scope,
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
    detectors = build_detectors(
        rulepack, ner_service_url=ctx.ner_service_url, ner_scope=ctx.ner_scope
    )
    ner_detector = next((d for d in detectors if isinstance(d, NERDetector)), None)
    metadata_detectors = detectors if ctx.ner_scope == "all" else history_detectors
    history_ner = ner_detector if ctx.ner_scope == "all" else None
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
        ctx, metadata_detectors, "history_scan_pre.json"
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in commit metadata (%.1fs)", _finding_summary(ctx.history_pre_findings), elapsed)

    # Step 6b: History blob scan — file contents (all commits/branches)
    logger.info("Scanning history (file blobs)...")
    t0 = time.perf_counter()
    ctx.history_blob_pre_findings = run_history_blob_scan(
        ctx, history_detectors, "history_blob_scan_pre.json", ner_detector=history_ner
    )
    elapsed = time.perf_counter() - t0
    ctx.timings["steps"]["history_blob_scan_pre"] = round(elapsed, 3)
    logger.info("Found %s in historical blobs (%.1fs)", _finding_summary(ctx.history_blob_pre_findings), elapsed)

    ctx.timings["total_s"] = round(time.perf_counter() - t_total, 3)
    _patch_result_json(ctx)

    all_findings = ctx.pre_findings + ctx.history_pre_findings + ctx.history_blob_pre_findings
    logger.info("Scan complete: %s (%.1fs)", _finding_summary(all_findings), ctx.timings["total_s"])

    return 0 if not all_findings else 1


def run_apply_map(
    source: str,
    out_dir: Path,
    brand_map_path: Path,
    salt_env: str = "REPO_SANITIZER_SALT",
    rev: str = "HEAD",
) -> int:
    """Pass-3: apply a Pass-2 tiered brand map across ALL history, then bundle.

    ``source`` is the Pass-1 output (its ``work`` dir or ``sanitized.bundle``);
    the brand map is the ``{pattern, replacement, is_regex, preserve_case}`` file
    Pass-2 produced. One git-filter-repo pass rewrites every blob, commit message,
    and path segment, then a fresh bundle is written. The mandatory Pass-2
    codex/agent audit still runs after this — apply-map is mechanical, not a gate.
    """
    from repo_sanitizer.redaction.history_ops import detect_brand_map_collisions, load_brand_map
    from repo_sanitizer.steps.history_rewrite import run_brand_map_rewrite, verify_brand_map_applied

    rows = load_brand_map(brand_map_path)
    if not rows:
        logger.warning("Brand map %s has no usable rules — nothing to apply.", brand_map_path)
        return 1

    # Advisory: ≥2 distinct brands collapsed onto one placeholder — the
    # dup-identifier / invalid-`acme1,` Pass-2 failure mode. NOT a hard fail
    # (tiered maps may reuse a placeholder across their own tiers); the mandatory
    # coherence audit judges. Logged loudly here before any history is touched.
    for replacement, patterns in detect_brand_map_collisions(rows).items():
        logger.warning(
            "brand-map collision: %d distinct patterns → %r: %s%s",
            len(patterns), replacement,
            ", ".join(patterns[:8]), " …" if len(patterns) > 8 else "",
        )

    ctx = RunContext.create(
        source=source,
        out_dir=out_dir,
        rulepack_path=Path(brand_map_path).resolve(),  # placeholder; rulepack is not loaded
        salt_env=salt_env,
        rev=rev,
    )

    t_total = time.perf_counter()
    fetch(ctx, source)
    logger.info("Applying brand map (%d rules) across all history...", len(rows))
    run_brand_map_rewrite(ctx, rows)

    # Verify the map FULLY applied (a surviving pattern = a blob/path the rewrite
    # could not decode/rewrite). Does NOT certify brand-completeness — a brand the
    # map never listed is the mandatory Pass-2 codex/agent audit's job.
    # Keep all branches (now also brand-scrubbing their NAMES), drop tags/remotes,
    # set HEAD — BEFORE verification so verify scopes to the shipped refs (heads)
    # only, not content in tags/remotes that will not ship.
    run_ref_reconcile(ctx, brand_map_rows=rows)
    survivors = verify_brand_map_applied(ctx, rows)
    run_package(ctx)
    elapsed = time.perf_counter() - t_total
    bundle = ctx.out_dir / "output" / "sanitized.bundle"
    if survivors:
        brand_survivors = [s for s in survivors if not s.startswith("json-invalid:")]
        json_failures = [s for s in survivors if s.startswith("json-invalid:")]
        if brand_survivors:
            logger.error(
                "apply-map: %d brand-map pattern(s) STILL MATCH after rewrite (incomplete "
                "application): %s%s",
                len(brand_survivors),
                ", ".join(brand_survivors[:10]),
                " …" if len(brand_survivors) > 10 else "",
            )
        if json_failures:
            logger.error(
                "apply-map: %d build manifest(s) became INVALID JSON after the brand rewrite: "
                "%s%s",
                len(json_failures),
                ", ".join(json_failures[:10]),
                " …" if len(json_failures) > 10 else "",
            )
        logger.error("Bundle written to %s but apply-map FAILED verification (exit 1).", bundle)
        return 1
    logger.info("apply-map complete (%.1fs) → %s", elapsed, bundle)
    return 0


def _converge_redaction(ctx: RunContext, detectors: list, max_passes: int = 3) -> None:
    """Re-redact working-tree residuals until the scan stabilizes (≤max_passes).

    Masking the first high-entropy token can promote a NEW substring to gitleaks'
    top match on the next scan; a single redact pass then leaves residuals that
    fail the gate. Loop redact→inventory→scan until the *redactable* finding count
    stops decreasing. Brand findings are detection-only (never redacted, gated as
    the Pass-2 worklist) — they are excluded from the convergence signal so the
    loop does not spin on them. ``ctx.post_findings`` is left as the final scan
    (brands included) for the gate; the manifest accumulates across all passes.
    """
    from repo_sanitizer.detectors.base import is_detection_only

    def _redactable(findings: list) -> list:
        return [f for f in findings if not is_detection_only(f)]

    accumulated = list(ctx.redaction_manifest)  # Step-4 redactions, preserved
    prev_fp: frozenset | None = None
    for _pass in range(max_passes):
        residual = _redactable(ctx.post_findings)
        if not residual:
            break
        # Fingerprint by identity, not count: a gitleaks cascade can ROTATE one
        # secret into another (same count, different value) — counting would stop
        # early and leave the newly surfaced secret. Stop only when the exact set
        # of residual findings repeats (irreducible) or empties.
        fp = frozenset((f.file_path, f.value_hash) for f in residual)
        if fp == prev_fp:
            break
        prev_fp = fp
        run_redact(ctx, residual)
        accumulated.extend(ctx.redaction_manifest)  # run_redact overwrites; merge
        run_inventory(ctx)
        ctx.post_findings = run_scan(ctx, detectors, "scan_report_post.json")

    ctx.redaction_manifest = accumulated
    (ctx.artifacts_dir / "redaction_manifest.json").write_text(
        json.dumps(accumulated, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    resid = _redactable(ctx.post_findings)
    if resid:
        logger.info("Post-scan residual after convergence: %s", _finding_summary(resid))


def _patch_result_json(ctx: RunContext) -> None:
    """Merge ctx.timings (with final total_s) into artifacts/result.json."""
    result_path = ctx.artifacts_dir / "result.json"
    doc = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
    doc["timings"] = ctx.timings
    result_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
