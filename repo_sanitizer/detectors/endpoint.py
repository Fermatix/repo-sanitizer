from __future__ import annotations

import ipaddress
import re

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)

INTERNAL_TLDS = (".internal", ".corp", ".local", ".lan", ".intra")

PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:(?:10\.(?:\d{1,3}\.){2}\d{1,3})"
    r"|(?:172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})"
    r"|(?:192\.168\.(?:\d{1,3}\.)\d{1,3}))\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,})\b"
)


class EndpointDetector(Detector):
    """Detect internal domains, private IPs, and internal system URLs."""

    def __init__(self, domain_list: list[str] | None = None) -> None:
        self.domain_list = {d.lower() for d in (domain_list or [])}

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        findings.extend(self._detect_private_ips(target))
        findings.extend(self._detect_internal_domains(target))
        return findings

    def _detect_private_ips(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for m in PRIVATE_IP_PATTERN.finditer(target.content):
            start, end = m.start(), m.end()
            if not self._in_zones(target, start, end):
                continue
            try:
                ip = ipaddress.ip_address(m.group())
                if ip.is_private:
                    line = target.content[:start].count("\n") + 1
                    findings.append(
                        Finding(
                            detector="EndpointDetector",
                            category=Category.ENDPOINT,
                            severity=Severity.MEDIUM,
                            file_path=target.file_path,
                            line=line,
                            offset_start=start,
                            offset_end=end,
                            matched_value=m.group(),
                        )
                    )
            except ValueError:
                pass
        return findings

    def _detect_internal_domains(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for m in DOMAIN_PATTERN.finditer(target.content):
            domain = m.group().lower()
            start, end = m.start(), m.end()
            if not self._in_zones(target, start, end):
                continue
            is_internal = any(domain.endswith(tld) for tld in INTERNAL_TLDS)
            is_in_list = domain in self.domain_list or any(
                domain.endswith("." + d) for d in self.domain_list
            )
            if is_internal or is_in_list:
                line = target.content[:start].count("\n") + 1
                findings.append(
                    Finding(
                        detector="EndpointDetector",
                        category=Category.ENDPOINT,
                        severity=Severity.MEDIUM,
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
