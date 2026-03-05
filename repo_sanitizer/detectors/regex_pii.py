from __future__ import annotations

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)
from repo_sanitizer.rulepack import PIIPattern


class RegexPIIDetector(Detector):
    """Detect PII using regex patterns from rulepack."""

    def __init__(self, patterns: list[PIIPattern]) -> None:
        self.patterns = patterns

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for pat in self.patterns:
            for m in pat.pattern.finditer(target.content):
                start, end = m.start(), m.end()
                if not self._in_zones(target, start, end):
                    continue
                line = target.content[:start].count("\n") + 1
                findings.append(
                    Finding(
                        detector="RegexPIIDetector",
                        category=Category(pat.category)
                        if pat.category in Category.__members__
                        else Category.PII,
                        severity=Severity(pat.severity)
                        if pat.severity in Severity.__members__
                        else Severity.HIGH,
                        file_path=target.file_path,
                        line=line,
                        offset_start=start,
                        offset_end=end,
                        matched_value=m.group(),
                    )
                )
        return findings

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)
