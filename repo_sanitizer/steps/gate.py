from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from repo_sanitizer.context import FileAction, RunContext
from repo_sanitizer.detectors.base import Category, Finding, Severity
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


GATE_DEFINITIONS = {
    "SECRETS": {
        "description": "No secret findings remain after sanitization",
        "check": lambda f: f.category == Category.SECRET,
    },
    "PII_HIGH": {
        "description": "No high-severity PII findings remain",
        "check": lambda f: f.category == Category.PII and f.severity == Severity.HIGH,
    },
    "DICTIONARY": {
        "description": "No corporate dictionary matches remain",
        "check": lambda f: f.category == Category.DICTIONARY,
    },
    "ENDPOINTS": {
        "description": "No internal domains/IPs remain",
        "check": lambda f: f.category == Category.ENDPOINT,
    },
}


def run_gate_check(ctx: RunContext) -> dict:
    rulepack: Rulepack = ctx.rulepack
    results = {}
    gate_timings: dict[str, float] = {}

    # Combine all post-sanitization findings (working tree + commit metadata + historical blobs)
    all_post = ctx.post_findings + ctx.history_post_findings + ctx.history_blob_post_findings

    for gate_name, gate_def in GATE_DEFINITIONS.items():
        t0 = time.perf_counter()
        failing = [f for f in all_post if gate_def["check"](f)]
        gate_timings[gate_name] = round(time.perf_counter() - t0, 4)
        results[gate_name] = {
            "passed": len(failing) == 0,
            "description": gate_def["description"],
            "failing_count": len(failing),
        }

    # FORBIDDEN_FILES gate
    t0 = time.perf_counter()
    forbidden = _check_forbidden_files(ctx)
    gate_timings["FORBIDDEN_FILES"] = round(time.perf_counter() - t0, 4)
    results["FORBIDDEN_FILES"] = {
        "passed": len(forbidden) == 0,
        "description": "No forbidden files in output or history",
        "failing_count": len(forbidden),
        "files": forbidden,
    }

    # CONFIGS gate
    t0 = time.perf_counter()
    config_violations = _check_configs(ctx)
    gate_timings["CONFIGS"] = round(time.perf_counter() - t0, 4)
    results["CONFIGS"] = {
        "passed": len(config_violations) == 0,
        "description": "No config files without allowed suffix in output",
        "failing_count": len(config_violations),
        "files": config_violations,
    }

    ctx.timings.setdefault("gates", {}).update(gate_timings)

    all_passed = all(g["passed"] for g in results.values())
    exit_code = 0 if all_passed else 1

    result_doc = {
        "exit_code": exit_code,
        "all_passed": all_passed,
        "gates": results,
        "timings": ctx.timings,
        "summary": {
            "total_pre_findings": len(ctx.pre_findings),
            "total_post_findings": len(ctx.post_findings),
            "total_history_pre_findings": len(ctx.history_pre_findings),
            "total_history_post_findings": len(ctx.history_post_findings),
            "total_history_blob_pre_findings": len(ctx.history_blob_pre_findings),
            "total_history_blob_post_findings": len(ctx.history_blob_post_findings),
            "total_redactions": len(ctx.redaction_manifest),
        },
    }

    artifact_path = ctx.artifacts_dir / "result.json"
    artifact_path.write_text(
        json.dumps(result_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    for name, gate in results.items():
        if gate["passed"]:
            logger.debug("Gate %s: PASS", name)
        else:
            logger.warning("Gate %s FAIL: %d findings remain", name, gate["failing_count"])

    return result_doc


def _check_forbidden_files(ctx: RunContext) -> list[str]:
    rulepack: Rulepack = ctx.rulepack
    forbidden = []
    for item in ctx.inventory:
        if item.action == FileAction.DELETE:
            file_path = ctx.work_dir / item.path
            if file_path.exists():
                forbidden.append(item.path)
    return forbidden


def _check_configs(ctx: RunContext) -> list[str]:
    rulepack: Rulepack = ctx.rulepack
    violations = []
    from fnmatch import fnmatch

    for item in ctx.inventory:
        for glob_pat in rulepack.deny_globs:
            pat = glob_pat.split("/")[-1]
            if fnmatch(item.path.split("/")[-1], pat):
                has_allow = any(item.path.endswith(s) for s in rulepack.allow_suffixes)
                if not has_allow:
                    file_path = ctx.work_dir / item.path
                    if file_path.exists():
                        violations.append(item.path)
                break
    return violations
