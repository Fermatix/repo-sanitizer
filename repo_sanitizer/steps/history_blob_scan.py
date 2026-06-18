from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from repo_sanitizer.context import RunContext
from repo_sanitizer.detectors.base import Detector, Finding, ScanTarget
from repo_sanitizer.encoding import decode_bytes_detect
from repo_sanitizer.rulepack import Rulepack

if TYPE_CHECKING:
    from repo_sanitizer.detectors.ner import NERDetector

logger = logging.getLogger(__name__)


def build_history_detectors(rulepack: Rulepack) -> list[Detector]:
    """Detectors for history blob scanning (per-blob inner loop).

    SecretsDetector (gitleaks) is excluded: calling it once per blob via
    subprocess would be prohibitively slow for large histories.
    NERDetector is excluded here too — it is run once in batch after the loop
    via ``run_history_blob_scan(ner_detector=...)``.

    Uses the same keep-list / domains-split / variant-expanded brand terms as
    the working-tree ``build_detectors`` so history and working tree agree on
    what is (and is not) a leak. Brand-in-identifier / brand-in-path structural
    passes are working-tree-only (not run over history blobs).
    """
    from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
    from repo_sanitizer.detectors.dictionary import DictionaryDetector
    from repo_sanitizer.detectors.endpoint import EndpointDetector
    from repo_sanitizer.steps.scan import build_brand_terms

    brand_terms, keep = build_brand_terms(rulepack)

    detectors: list[Detector] = []
    if rulepack.pii_patterns:
        detectors.append(RegexPIIDetector(rulepack.pii_patterns))
    if brand_terms:
        detectors.append(DictionaryDetector({"brands": brand_terms}, keep=keep))
    domain_list = rulepack.dictionaries.get("domains", [])
    detectors.append(EndpointDetector(domain_list, keep=keep))
    return detectors


def run_history_blob_scan(
    ctx: RunContext,
    detectors: list[Detector],
    report_name: str = "history_blob_scan_pre.json",
    ner_detector: Optional["NERDetector"] = None,
) -> list[Finding]:
    """Scan file contents of every unique blob reachable from any branch or tag.

    ``detectors`` runs per-blob (fast, subprocess-free detectors only).
    ``ner_detector``, when provided, is applied once in a single batched
    inference call over all decoded blobs after the per-blob loop completes.
    """
    rulepack: Rulepack = ctx.rulepack
    work_dir = ctx.work_dir

    blobs = _collect_all_blobs(work_dir)
    logger.info("Scanning %d blobs...", len(blobs))

    all_findings: list[Finding] = []
    detector_times: dict[str, float] = {type(d).__name__: 0.0 for d in detectors}
    if ner_detector is not None:
        detector_times["NERDetector"] = 0.0
    skipped_binary = 0
    skipped_large = 0
    ner_targets: list[ScanTarget] = []

    for blob_sha, path in blobs:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""

        # Skip known binary extensions
        if ext in rulepack.binary_deny_extensions or ext in rulepack.binary_allow_extensions:
            skipped_binary += 1
            continue

        result = subprocess.run(
            ["git", "cat-file", "blob", blob_sha],
            cwd=str(work_dir),
            capture_output=True,
        )
        if result.returncode != 0:
            continue

        raw = result.stdout

        # Skip binary blobs (null bytes in first 8 KB)
        if b"\x00" in raw[:8192]:
            skipped_binary += 1
            continue

        # Skip oversized blobs
        if len(raw) > rulepack.max_file_mb * 1024 * 1024:
            skipped_large += 1
            continue

        content, _enc = decode_bytes_detect(raw)

        # Use a virtual path that indicates this is a historical blob
        virtual_path = f"<history:{blob_sha[:8]}/{path}>"
        target = ScanTarget(file_path=virtual_path, content=content)

        for detector in detectors:
            t0 = time.perf_counter()
            try:
                findings = detector.detect(target)
                for f in findings:
                    f.compute_hash(ctx.salt)
                all_findings.extend(findings)
            except Exception as e:
                logger.debug(
                    "Detector %s failed on blob %s: %s",
                    type(detector).__name__,
                    blob_sha[:8],
                    e,
                )
            finally:
                detector_times[type(detector).__name__] += time.perf_counter() - t0

        if ner_detector is not None:
            ner_targets.append(target)

    # NER batch pass — all blobs in one inference call
    if ner_detector is not None and ner_targets:
        logger.info("Running NER on %d history blobs...", len(ner_targets))
        t0 = time.perf_counter()
        try:
            ner_findings = ner_detector.detect_batch(ner_targets)
            for f in ner_findings:
                f.compute_hash(ctx.salt)
            all_findings.extend(ner_findings)
        except Exception as e:
            logger.warning("NER history blob scan failed: %s", e)
        finally:
            detector_times["NERDetector"] += time.perf_counter() - t0

    scan_key = report_name.removesuffix(".json")
    ctx.timings.setdefault("detectors", {})[scan_key] = {
        k: round(v, 3) for k, v in detector_times.items()
    }
    logger.debug(
        "History blob scan '%s': %d findings  (skipped: %d binary, %d oversized)",
        report_name,
        len(all_findings),
        skipped_binary,
        skipped_large,
    )

    artifact_path = ctx.artifacts_dir / report_name
    artifact_path.write_text(
        json.dumps(
            [f.to_report() for f in all_findings],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return all_findings


def _collect_all_blobs(work_dir: Path) -> list[tuple[str, str]]:
    """Return unique (blob_sha, path) pairs reachable from any ref.

    Uses a single git pipeline:
        git rev-list --objects --all
        | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)'

    This is O(total_objects) and avoids one subprocess call per commit.
    Each unique blob is returned once, even if it appears in many commits.
    """
    rev_list = subprocess.Popen(
        ["git", "rev-list", "--objects", "--all"],
        stdout=subprocess.PIPE,
        cwd=str(work_dir),
    )
    cat_file = subprocess.Popen(
        ["git", "cat-file", "--batch-check=%(objecttype) %(objectname) %(rest)"],
        stdin=rev_list.stdout,
        stdout=subprocess.PIPE,
        cwd=str(work_dir),
    )
    # Allow rev_list to receive SIGPIPE if cat_file exits early
    assert rev_list.stdout is not None
    rev_list.stdout.close()

    output, _ = cat_file.communicate()
    rev_list.wait()

    seen: set[str] = set()
    blobs: list[tuple[str, str]] = []

    for line in output.decode("utf-8", errors="replace").splitlines():
        # Format: "blob <sha> <path>" | "tree <sha> <path>" | "commit <sha>"
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0] == "blob":
            blob_sha = parts[1]
            path = parts[2].strip()
            if path and blob_sha not in seen:
                seen.add(blob_sha)
                blobs.append((blob_sha, path))

    return blobs
