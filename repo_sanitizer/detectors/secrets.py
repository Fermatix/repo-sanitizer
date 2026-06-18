from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)


# Exact placeholder-mask shapes emitted by redaction/replacements.py and
# redaction/history_ops.py (every hash is 12 hex; domain/endpoint masks 8 hex).
# gitleaks would otherwise re-flag OUR OWN masks as high-entropy secrets, so the
# post-scan + re-redact convergence loop would never settle. The regexes are
# ANCHORED with \b and pinned to the exact hash length so a REAL secret that
# merely contains such a substring is NOT suppressed (regexTarget="match").
_MASK_ALLOWLIST_REGEXES = (
    r"\bREDACTED_(?:EMAIL_|IP_|JWT_|URL_)?[0-9a-fA-F]{12}\b",
    r"\bTERM_[0-9a-fA-F]{12}\b",
    r"\bANON_(?:PER|ORG)_[0-9a-fA-F]{12}\b",
    r"\bAuthor_[0-9a-fA-F]{12}\b",
    r"\b(?:user|author)_[0-9a-fA-F]{12}@example\.invalid\b",
    r"\b[0-9a-fA-F]{8}\.example\.invalid\b",
)


def build_gitleaks_config(allowlist_masks: bool = True) -> str:
    """Return a gitleaks TOML config string.

    Uses SINGLE-QUOTED TOML literal strings for the regexes so backslash regex
    metacharacters (``\\.``, ``\\b``) are NOT interpreted as TOML escapes — a
    double-quoted ``"\\."`` is INVALID TOML and makes gitleaks fail to load the
    config (which, if the failure is swallowed, silently disables detection).
    ``[extend] useDefault = true`` keeps every built-in rule; passing this via
    ``--config`` also OVERRIDES any ``.gitleaks.toml`` shipped in the scanned
    repo, so a partner repo cannot allowlist its own secrets past us.
    """
    lines = ["[extend]", "useDefault = true", ""]
    if allowlist_masks:
        lines += [
            "[allowlist]",
            'description = "repo-sanitizer placeholder masks"',
            'regexTarget = "match"',
            "regexes = [",
        ]
        lines += [f"  '{rx}'," for rx in _MASK_ALLOWLIST_REGEXES]
        lines.append("]")
    return "\n".join(lines) + "\n"


class SecretsDetector(Detector):
    """Wrapper over gitleaks for secret detection."""

    def __init__(self) -> None:
        if not shutil.which("gitleaks"):
            raise RuntimeError(
                "gitleaks is not installed or not found in PATH. "
                "Install it: https://github.com/gitleaks/gitleaks#installing"
            )
        # Validate the self-mask config loads AND detection actually fires, ONCE,
        # at construction. run_scan() swallows per-file detector exceptions, so a
        # broken config caught only inside detect() would silently disable secret
        # detection. Constructing happens in build_detectors (outside that
        # try/except), so raising here fails the pipeline closed at startup.
        self._validate()
        # {relpath: [gitleaks_item,...]} from a one-shot whole-tree scan set by
        # prescan_tree(). When set, detect() serves from it instead of spawning
        # gitleaks PER FILE (thousands of spawns × convergence passes). None =
        # per-file fallback (e.g. history-blob scan, which has no work-tree).
        self._cache: dict | None = None

    def prescan_tree(self, work_dir) -> None:
        """Run gitleaks ONCE over the whole work tree; cache findings by relpath.

        Same config/flags as the per-file detect() path (self-mask allowlist +
        --ignore-gitleaks-allow), so results are identical — only batched. Raises
        on a fatal gitleaks failure (no report); run_scan catches it and falls
        back to per-file scanning. Callers that want the strict per-file path
        simply don't call this (cache stays None).
        """
        work_dir = Path(work_dir)
        cache: dict[str, list] = {}
        with tempfile.TemporaryDirectory() as cfgdir:
            report_file = Path(cfgdir) / "report.json"
            cfg_file = Path(cfgdir) / "gitleaks.toml"
            cfg_file.write_text(build_gitleaks_config(allowlist_masks=True), encoding="utf-8")
            subprocess.run(
                ["gitleaks", "detect", "--no-git", "--source", str(work_dir),
                 "--config", str(cfg_file), "--ignore-gitleaks-allow",
                 "--report-format", "json", "--report-path", str(report_file)],
                capture_output=True, text=True,
            )
            if not report_file.exists():
                raise RuntimeError(
                    "gitleaks did not produce a report during tree prescan "
                    "(fatal config/install error)."
                )
            try:
                items = json.loads(report_file.read_text() or "[]")
            except json.JSONDecodeError:
                items = []
            for it in items:
                raw = it.get("File") or ""
                # gitleaks reports an ABSOLUTE path; map to the relative path used
                # by ScanTarget.file_path (== inventory item.path).
                try:
                    rel = os.path.relpath(raw, str(work_dir))
                except ValueError:
                    rel = raw
                cache.setdefault(rel.replace("\\", "/"), []).append(it)
        self._cache = cache

    def _validate(self) -> None:
        # A high-entropy generic key reliably flagged by gitleaks (generic-api-key).
        # NOT a provider-token shape (Slack/AWS/…) — those trip GitHub push
        # protection when this source is committed.
        probe = "api_key=Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk\n"
        with tempfile.TemporaryDirectory() as tmpdir, \
                tempfile.TemporaryDirectory() as cfgdir:
            (Path(tmpdir) / "probe.txt").write_text(probe, encoding="utf-8")
            report_file = Path(tmpdir) / "report.json"
            cfg_file = Path(cfgdir) / "gitleaks.toml"
            cfg_file.write_text(build_gitleaks_config(allowlist_masks=True), encoding="utf-8")
            result = subprocess.run(
                ["gitleaks", "detect", "--no-git", "--source", tmpdir,
                 "--config", str(cfg_file), "--ignore-gitleaks-allow",
                 "--report-format", "json", "--report-path", str(report_file)],
                capture_output=True, text=True,
            )
            if not report_file.exists():
                raise RuntimeError(
                    "gitleaks failed to load the self-mask config "
                    f"(detection would be silently disabled): {result.stderr.strip()[:300]}"
                )
            try:
                found = json.loads(report_file.read_text())
            except json.JSONDecodeError:
                found = []
            if not found:
                raise RuntimeError(
                    "gitleaks did not detect the probe secret under the self-mask "
                    "config — secret detection is broken; refusing to proceed."
                )

    def detect(self, target: ScanTarget) -> list[Finding]:
        # Fast path: serve from the one-shot whole-tree prescan cache (set by
        # prescan_tree) instead of spawning gitleaks per file. Builds Findings
        # identically to the per-file path below.
        if self._cache is not None:
            findings = []
            for item in self._cache.get(target.file_path, []):
                secret = item.get("Secret", "")
                start_line = item.get("StartLine", 1)
                end_line = item.get("EndLine", start_line)
                start_col = item.get("StartColumn", 0)
                end_col = item.get("EndColumn", 0)
                offset_start = _find_offset(target.content, start_line, start_col)
                offset_end = _find_offset(target.content, end_line, end_col)
                if self._in_zones(target, offset_start, offset_end):
                    findings.append(
                        Finding(
                            detector="SecretsDetector",
                            category=Category.SECRET,
                            severity=Severity.CRITICAL,
                            file_path=target.file_path,
                            line=start_line,
                            offset_start=offset_start,
                            offset_end=offset_end,
                            matched_value=secret,
                        )
                    )
            return findings
        with tempfile.TemporaryDirectory() as tmpdir, \
                tempfile.TemporaryDirectory() as cfgdir:
            tmp_file = Path(tmpdir) / Path(target.file_path).name
            tmp_file.write_text(target.content, encoding="utf-8")
            report_file = Path(tmpdir) / "report.json"
            # Config lives OUTSIDE the scanned source dir so it isn't itself scanned.
            cfg_file = Path(cfgdir) / "gitleaks.toml"
            cfg_file.write_text(build_gitleaks_config(allowlist_masks=True), encoding="utf-8")

            result = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--no-git",
                    "--source",
                    tmpdir,
                    "--config",
                    str(cfg_file),
                    # Defeat partner `# gitleaks:allow` comments suppressing leaks.
                    "--ignore-gitleaks-allow",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_file),
                ],
                capture_output=True,
                text=True,
            )

            # FAIL CLOSED: gitleaks writes the report on success (even with 0 or N
            # leaks). A MISSING report means a fatal error (bad config / install) —
            # returning [] would silently disable secret detection. Raise instead.
            if not report_file.exists():
                raise RuntimeError(
                    "gitleaks did not produce a report (fatal config/install error); "
                    f"refusing to treat as 'no secrets'. stderr: {result.stderr.strip()[:300]}"
                )

            findings = []
            if report_file.exists():
                try:
                    raw = json.loads(report_file.read_text())
                except json.JSONDecodeError:
                    return findings

                for item in raw:
                    secret = item.get("Secret", "")
                    start_line = item.get("StartLine", 1)
                    end_line = item.get("EndLine", start_line)
                    start_col = item.get("StartColumn", 0)
                    end_col = item.get("EndColumn", 0)

                    offset_start = _find_offset(
                        target.content, start_line, start_col
                    )
                    offset_end = _find_offset(
                        target.content, end_line, end_col
                    )

                    if self._in_zones(target, offset_start, offset_end):
                        findings.append(
                            Finding(
                                detector="SecretsDetector",
                                category=Category.SECRET,
                                severity=Severity.CRITICAL,
                                file_path=target.file_path,
                                line=start_line,
                                offset_start=offset_start,
                                offset_end=offset_end,
                                matched_value=secret,
                            )
                        )
            return findings

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)


def _find_offset(content: str, line: int, col: int) -> int:
    """Map a gitleaks (1-based line, 1-based column) to a character offset.

    gitleaks reports columns as BYTE offsets within the line; treating them as
    character offsets misplaces the span on lines containing multibyte (e.g.
    Cyrillic) characters. Decode the line's bytes up to the column to recover
    the character column. For ASCII this is identical to the previous behavior.
    """
    lines = content.split("\n")
    idx = min(max(line - 1, 0), len(lines) - 1) if lines else 0
    line_start = sum(len(prev) + 1 for prev in lines[:idx])  # +1 for each '\n'
    line_text = lines[idx] if idx < len(lines) else ""
    byte_col = max(col - 1, 0)
    char_col = len(
        line_text.encode("utf-8")[:byte_col].decode("utf-8", errors="replace")
    )
    return line_start + char_col
