from __future__ import annotations

import json
import logging
import subprocess
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
        "description": "No internal domains/public IPs remain",
        "check": lambda f: f.category == Category.ENDPOINT,
    },
    # Brand worklist gates (Pass-1 detection-only → intentionally RED until the
    # Pass-2 coherent brand → AcmeN rename + re-scan drives them to zero).
    "ORG_NAME": {
        "description": "No organization-name (brand) findings remain — Pass-2 worklist",
        "check": lambda f: f.category == Category.ORG_NAME,
    },
    "BRAND_IDENTIFIER": {
        "description": "No brands surviving in code identifiers — Pass-2 worklist",
        "check": lambda f: f.category == Category.BRAND_IDENTIFIER,
    },
    "BRAND_PATH": {
        "description": "No brands surviving in file/dir path names — Pass-2 worklist",
        "check": lambda f: f.category == Category.BRAND_PATH,
    },
    "PACKAGE_NAMESPACE": {
        "description": "No brands surviving in package/namespace/import declarations — Pass-2 worklist",
        "check": lambda f: f.category == Category.PACKAGE_NAMESPACE,
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

    # PARSEABLE_CONFIGS gate (blocking) — build-smoke. Redaction must not turn a
    # structured config that PARSED before into one that does not parse after (the
    # dominant ship-blocking defect: a placeholder spliced into YAML/JSON/XML/csproj/
    # TOML syntax). Only valid→invalid regressions count (a pre-broken or deleted
    # file is not flagged), so a clean repo never false-fails.
    t0 = time.perf_counter()
    config_breaks = _check_parseable_configs(ctx)
    gate_timings["PARSEABLE_CONFIGS"] = round(time.perf_counter() - t0, 4)
    results["PARSEABLE_CONFIGS"] = {
        "passed": len(config_breaks) == 0,
        "description": "No structured config (JSON/YAML/XML/csproj/TOML) broken by redaction",
        "failing_count": len(config_breaks),
        "files": config_breaks[:50],
    }

    # NO_TAGS gate (blocking) — ref-reconcile must have dropped every tag.
    t0 = time.perf_counter()
    leftover_tags = _list_refs(ctx, "refs/tags")
    gate_timings["NO_TAGS"] = round(time.perf_counter() - t0, 4)
    results["NO_TAGS"] = {
        "passed": len(leftover_tags) == 0,
        "description": "No tags in the output bundle (all tags dropped)",
        "failing_count": len(leftover_tags),
        "refs": leftover_tags[:50],
    }

    # BRANCHES_PRESERVED gate (blocking in the LOSS direction) — every intake
    # branch must be accounted for (kept under a scrubbed slug, or legitimately
    # pruned to nothing), and every kept slug must exist on disk. Keeping all
    # branches is the overriding priority, so an unaccounted-for loss fails.
    t0 = time.perf_counter()
    lost = _check_branches_preserved(ctx)
    gate_timings["BRANCHES_PRESERVED"] = round(time.perf_counter() - t0, 4)
    results["BRANCHES_PRESERVED"] = {
        "passed": len(lost) == 0,
        "description": "Every intake branch survives in the output (or pruned to nothing)",
        "failing_count": len(lost),
        "branches": lost[:50],
    }

    # CLEAN_REF_NAMES gate (NON-BLOCKING warning) — residual brand/PII detectable
    # in a shipped branch name. Per the user's priority (keep all branches even at
    # some leak cost), this never blocks or drops a branch; it surfaces names for
    # the mandatory Pass-2 audit.
    t0 = time.perf_counter()
    dirty_names = _check_ref_names(ctx)
    gate_timings["CLEAN_REF_NAMES"] = round(time.perf_counter() - t0, 4)
    results["CLEAN_REF_NAMES"] = {
        "passed": len(dirty_names) == 0,
        "blocking": False,
        "description": "No brand/PII detected in shipped branch names (advisory)",
        "failing_count": len(dirty_names),
        "names": dirty_names[:50],
    }

    ctx.timings.setdefault("gates", {}).update(gate_timings)

    all_passed = all(g["passed"] for g in results.values() if g.get("blocking", True))
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
        elif not gate.get("blocking", True):
            logger.warning("Gate %s ADVISORY: %d item(s) — non-blocking", name, gate["failing_count"])
        else:
            logger.warning("Gate %s FAIL: %d findings remain", name, gate["failing_count"])

    return result_doc


def _list_refs(ctx: RunContext, prefix: str) -> list[str]:
    """Short names of refs under ``prefix`` (e.g. 'refs/tags') in the work dir.

    Returns [] if the work dir is absent or not a git repo (gate unit tests
    construct a ctx with no real work tree)."""
    try:
        r = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname:short)", prefix],
            cwd=str(ctx.work_dir), capture_output=True, text=True,
        )
    except (FileNotFoundError, NotADirectoryError):
        return []
    if r.returncode != 0:
        return []
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _check_branches_preserved(ctx: RunContext) -> list[str]:
    """Return intake branch names that were LOST (not kept and not pruned), plus
    kept slugs that are missing on disk. Empty = all branches preserved."""
    intake = set(ctx.intake_branch_tips or {})
    rename = ctx.branch_rename_map or {}
    lost = sorted(intake - set(rename))  # vanished without being accounted for
    heads = set(_list_refs(ctx, "refs/heads"))
    for name, slug in rename.items():
        if slug and slug not in heads:
            lost.append(f"{name}→{slug} (missing on disk)")
    return lost


def _check_ref_names(ctx: RunContext) -> list[str]:
    """Advisory: shipped branch names that still match a rulepack brand term or
    PII pattern. Cheap heuristic (no NER) reusing the loaded rulepack; skipped
    when no rulepack is loaded (e.g. apply-map)."""
    rulepack = getattr(ctx, "rulepack", None)
    if rulepack is None:
        return []
    heads = _list_refs(ctx, "refs/heads")
    if not heads:
        return []
    try:
        from repo_sanitizer.steps.scan import build_brand_terms
        terms, _keep = build_brand_terms(rulepack)
    except Exception:  # noqa: BLE001
        terms = set()
    lowered_terms = {t.lower() for t in terms if t and len(t) >= 3}
    dirty: list[str] = []
    for name in heads:
        low = name.lower()
        if any(t in low for t in lowered_terms):
            dirty.append(name)
            continue
        for p in rulepack.pii_patterns:
            try:
                if p.pattern.search(name):
                    dirty.append(name)
                    break
            except Exception:  # noqa: BLE001
                continue
    return dirty


def _check_parseable_configs(ctx: RunContext) -> list[str]:
    """Structured config files that PARSED before redaction and do NOT parse now.

    Re-parses the rewritten working tree and diffs against ``ctx.config_parse_pre``
    (snapshotted on the original tree). Empty pre-snapshot (e.g. apply-map, which
    builds its own check) ⇒ no regressions reported here."""
    pre = getattr(ctx, "config_parse_pre", None) or {}
    if not pre:
        return []
    from repo_sanitizer.buildsafe import config_parse_regressions, parse_status
    post = parse_status(ctx.work_dir)
    return config_parse_regressions(pre, post)


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
