from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

from repo_sanitizer.context import RunContext
from repo_sanitizer.detectors.base import Detector, Finding, ScanTarget
from repo_sanitizer.rulepack import Rulepack

logger = logging.getLogger(__name__)


def run_history_scan(
    ctx: RunContext,
    detectors: list[Detector],
    report_name: str = "history_scan_pre.json",
) -> list[Finding]:
    """Scan commit metadata (author, email, message) for PII."""
    all_findings: list[Finding] = []
    detector_times: dict[str, float] = {type(d).__name__: 0.0 for d in detectors}
    work_dir = ctx.work_dir

    log_format = "%H%n%an%n%ae%n%cn%n%ce%n%B%n---END---"
    cmd = ["git", "log", "--all", f"--format={log_format}"]
    if ctx.history_since:
        cmd.append(f"--since={ctx.history_since}")
    if ctx.history_until:
        cmd.append(f"--until={ctx.history_until}")

    result = subprocess.run(
        cmd,
        cwd=str(work_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.warning("git log failed: %s", result.stderr)
        return all_findings

    commits = _parse_log(result.stdout)

    for commit in commits:
        sha = commit["sha"]

        # Scan author/committer names and emails
        for field_name, value in [
            ("author_name", commit["author_name"]),
            ("author_email", commit["author_email"]),
            ("committer_name", commit["committer_name"]),
            ("committer_email", commit["committer_email"]),
        ]:
            target = ScanTarget(
                file_path=f"<commit:{sha[:8]}/{field_name}>",
                content=value,
            )
            for detector in detectors:
                t0 = time.perf_counter()
                try:
                    findings = detector.detect(target)
                    for f in findings:
                        f.compute_hash(ctx.salt)
                    all_findings.extend(findings)
                except Exception:
                    pass
                finally:
                    detector_times[type(detector).__name__] += time.perf_counter() - t0

        # Scan commit message
        if commit["message"].strip():
            target = ScanTarget(
                file_path=f"<commit:{sha[:8]}/message>",
                content=commit["message"],
            )
            for detector in detectors:
                t0 = time.perf_counter()
                try:
                    findings = detector.detect(target)
                    for f in findings:
                        f.compute_hash(ctx.salt)
                    all_findings.extend(findings)
                except Exception:
                    pass
                finally:
                    detector_times[type(detector).__name__] += time.perf_counter() - t0

    artifact_path = ctx.artifacts_dir / report_name
    artifact_path.write_text(
        json.dumps(
            [f.to_report() for f in all_findings],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    scan_key = report_name.removesuffix(".json")
    ctx.timings.setdefault("detectors", {})[scan_key] = {
        k: round(v, 3) for k, v in detector_times.items()
    }
    logger.debug("History scan '%s': %d findings", report_name, len(all_findings))
    return all_findings


def _parse_log(output: str) -> list[dict]:
    commits = []
    blocks = output.split("---END---")
    for block in blocks:
        lines = block.strip().split("\n")
        if len(lines) < 5:
            continue
        commits.append(
            {
                "sha": lines[0].strip(),
                "author_name": lines[1].strip(),
                "author_email": lines[2].strip(),
                "committer_name": lines[3].strip(),
                "committer_email": lines[4].strip(),
                "message": "\n".join(lines[5:]).strip(),
            }
        )
    return commits
