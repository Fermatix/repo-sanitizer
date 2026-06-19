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
from repo_sanitizer.encoding import read_text_detect


# Exact placeholder-mask shapes emitted by redaction/replacements.py and
# redaction/history_ops.py (every hash is 12 hex; domain/endpoint masks 8 hex).
# gitleaks would otherwise re-flag OUR OWN masks as high-entropy secrets, so the
# post-scan + re-redact convergence loop would never settle. The regexes are
# ANCHORED with \b and pinned to the exact hash length so a REAL secret that
# merely contains such a substring is NOT suppressed (regexTarget="match").
_MASK_ALLOWLIST_REGEXES = (
    # REDACTED_<hash> and REDACTED_<RULE_NAME>_<hash> — the latter is the
    # identifier-safe token the history scrubber emits for every non-URL PII/secret
    # pattern (e.g. REDACTED_GITHUB_TOKEN_<hash>, REDACTED_IBAN_<hash>), replacing
    # the old build-breaking "[name:hash]" markers.
    r"\bREDACTED_(?:[A-Z0-9_]+_)?[0-9a-fA-F]{12}\b",
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

    def prescan_tree(self, work_dir, scan_paths) -> None:
        """Run gitleaks ONCE over the SCAN set; cache findings by relpath.

        Builds a NEUTRAL staging tree ``<stage>/<index>/<basename>`` — one
        numbered subdir per scanned file holding its DECODED content — and runs
        gitleaks once over it. This makes the prescan EXACTLY equivalent to the
        per-file detect() path, not merely faster:

        - The per-file path copies each file to ``<tmp>/<basename>`` so gitleaks
          sees only the basename. gitleaks' ``useDefault`` allowlist filters by
          PATH (``node_modules/``, ``bower_components/``, parts of ``vendor/``,
          venv ``lib/``, ``*.dist-info/`` …), so scanning the real tree would
          SKIP secrets in those dirs that the per-file path FINDS. The neutral
          ``<index>`` dir defeats directory-based allowlisting; preserving the
          basename keeps any basename-based allowlist decision identical to the
          per-file path (intended: prescan == per-file, the per-file path is the
          reference).
        - It writes the SAME decoded text the per-file path writes
          (``read_text_detect`` == ``run_scan``'s decoder == per-file
          ``write_text(target.content)``), so gitleaks' reported line/col align
          with ``target.content`` for cp1251/UTF-16 files too.

        ``self._cache`` is cleared to ``None`` FIRST, so any failure / early
        raise leaves the per-file fallback active (never a stale cache). On
        success the cache holds EVERY scanned path (clean files map to ``[]``),
        so ``detect()`` can use cache MEMBERSHIP to decide cache-vs-per-file.
        Raises on a fatal gitleaks failure (no report); run_scan catches it and
        falls back to per-file scanning.
        """
        self._cache = None  # fail-safe: a raise below leaves per-file fallback
        work_dir = Path(work_dir)
        with tempfile.TemporaryDirectory() as stage_root, \
                tempfile.TemporaryDirectory() as meta_dir:
            stage = Path(stage_root)
            index_to_path: dict[str, str] = {}
            for i, rel in enumerate(scan_paths):
                rel = str(rel).replace("\\", "/")
                src = work_dir / rel
                try:
                    text, _enc = read_text_detect(src)
                except Exception:
                    # Unreadable here → not cached → per-file fallback for it.
                    continue
                idx = str(i)
                subdir = stage / idx
                subdir.mkdir(parents=True, exist_ok=True)
                basename = Path(rel).name or "file"
                try:
                    (subdir / basename).write_text(text, encoding="utf-8")
                except Exception:
                    continue
                index_to_path[idx] = rel

            report_file = Path(meta_dir) / "report.json"
            cfg_file = Path(meta_dir) / "gitleaks.toml"
            cfg_file.write_text(build_gitleaks_config(allowlist_masks=True), encoding="utf-8")
            subprocess.run(
                ["gitleaks", "detect", "--no-git", "--source", str(stage),
                 "--config", str(cfg_file), "--ignore-gitleaks-allow",
                 "--report-format", "json", "--report-path", str(report_file)],
                capture_output=True, text=True,
            )
            # FAIL CLOSED (shared parser): a missing / empty / invalid-JSON report
            # means gitleaks did not complete. self._cache stays None (set first),
            # so run_scan catches the raise and falls back to the per-file path —
            # NEVER seed a clean cache for the whole SCAN set from a bad report.
            items = _read_gitleaks_report(report_file, context="tree prescan")
            # Seed EVERY staged path so a clean file is a cache HIT (→ []), not a
            # miss (which would re-spawn gitleaks per-file). Membership = "was in
            # this prescan"; absence = "scan it per-file" (e.g. commit metadata).
            cache: dict[str, list] = {p: [] for p in index_to_path.values()}
            for it in items:
                raw = it.get("File") or ""
                try:
                    rel_in_stage = os.path.relpath(raw, str(stage)).replace("\\", "/")
                except ValueError:
                    continue
                idx = rel_in_stage.split("/", 1)[0]
                orig = index_to_path.get(idx)
                if orig is None:
                    continue
                cache[orig].append(it)
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
        # Fast path: serve from the one-shot prescan cache (set by prescan_tree)
        # instead of spawning gitleaks per file. Builds Findings identically to
        # the per-file path below. MEMBERSHIP-gated: a target not in the cache
        # (e.g. a synthetic <commit:.../field> metadata target, which is never a
        # SCAN relpath) is NOT a clean file — it was never prescanned, so it must
        # fall through to the per-file path rather than be served an empty [].
        #
        # Synthetic targets (commit metadata / history) use angle-bracket
        # file_paths like "<commit:abc12345/message>" (history_scan.py). A real
        # repo file could, in principle, be named the same string and be cached
        # as clean — then a --ner-scope all metadata target with that exact
        # file_path would be served the cached [] and NEVER scanned. Bypass the
        # cache for ANY "<...>" target: it is either synthetic (correctly
        # per-file scanned) or a real file whose name starts with "<" (also
        # correctly per-file scanned). Falling to per-file is always the SAFE
        # direction — it can never produce a false negative, only a slower scan.
        if (
            self._cache is not None
            and not target.file_path.startswith("<")
            and target.file_path in self._cache
        ):
            return self._build_findings(target, self._cache[target.file_path])
        with tempfile.TemporaryDirectory() as tmpdir, \
                tempfile.TemporaryDirectory() as cfgdir:
            tmp_file = Path(tmpdir) / Path(target.file_path).name
            tmp_file.write_text(target.content, encoding="utf-8")
            # BOTH the report and the config live OUTSIDE the scanned source dir
            # (cfgdir, not tmpdir). The report MUST NOT be in tmpdir: a scanned
            # file literally named "report.json" would otherwise share the path
            # with --report-path — gitleaks overwrites it with its own output, so
            # the file's secret is never scanned (a silent false negative).
            report_file = Path(cfgdir) / "report.json"
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

            # FAIL CLOSED (shared parser): a missing / empty / invalid-JSON report
            # means gitleaks did not complete — raise rather than return [] (which
            # would silently disable secret detection for this file). run_scan /
            # history_scan re-raise SecretsDetector failures so the pipeline aborts
            # rather than ship a missed secret.
            raw = _read_gitleaks_report(
                report_file, context="per-file scan", stderr=result.stderr
            )
            return self._build_findings(target, raw)

    def _build_findings(self, target: ScanTarget, items: list) -> list[Finding]:
        """Build Findings from gitleaks report items — the SINGLE construction
        path shared by the prescan-cache and per-file branches (so they can never
        diverge in how a leak is turned into a Finding)."""
        findings: list[Finding] = []
        for item in items:
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

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)


def _read_gitleaks_report(report_file: Path, *, context: str, stderr: str = "") -> list:
    """Read a gitleaks JSON report, FAILING CLOSED.

    A gitleaks run that DID complete writes ``"[]\\n"`` when clean (verified) and
    a JSON array otherwise. So a MISSING, EMPTY/whitespace, or invalid-JSON
    report all mean gitleaks did NOT complete — treating any of them as "no
    secrets" (returning ``[]``) would silently ship a leak. Raise instead; the
    caller decides whether to abort (per-file) or drop the cache and fall back
    (prescan). Shared by the prescan and per-file paths so they never diverge.
    """
    if not report_file.exists():
        raise RuntimeError(
            f"gitleaks did not produce a report ({context}); refusing to treat "
            f"as 'no secrets'. stderr: {stderr.strip()[:300]}"
        )
    text = report_file.read_text()
    if not text.strip():
        raise RuntimeError(
            f"gitleaks report was empty ({context}, truncated/killed run); "
            "refusing to treat as 'no secrets'."
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"gitleaks report was not valid JSON ({context}, truncated/corrupt "
            "run); refusing to treat as 'no secrets'."
        ) from e


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
