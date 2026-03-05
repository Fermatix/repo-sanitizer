from __future__ import annotations

import json
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


class SecretsDetector(Detector):
    """Wrapper over gitleaks for secret detection."""

    def __init__(self) -> None:
        if not shutil.which("gitleaks"):
            raise RuntimeError(
                "gitleaks is not installed or not found in PATH. "
                "Install it: https://github.com/gitleaks/gitleaks#installing"
            )

    def detect(self, target: ScanTarget) -> list[Finding]:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / Path(target.file_path).name
            tmp_file.write_text(target.content, encoding="utf-8")
            report_file = Path(tmpdir) / "report.json"

            result = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--no-git",
                    "--source",
                    tmpdir,
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_file),
                ],
                capture_output=True,
                text=True,
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
                    start_col = item.get("StartColumn", 0)
                    end_col = item.get("EndColumn", 0)

                    offset_start = _find_offset(
                        target.content, start_line, start_col
                    )
                    offset_end = _find_offset(
                        target.content, start_line, end_col
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
    current_line = 1
    offset = 0
    for i, ch in enumerate(content):
        if current_line == line:
            return offset + max(col - 1, 0)
        if ch == "\n":
            current_line += 1
            offset = i + 1
    return offset + max(col - 1, 0)
