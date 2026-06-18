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

# Dotted IPv4 quad. The lookarounds (not the \b shorthand) ensure an adjacent
# '.digit' suppresses the match, so the leading quad of a version string or OID
# (1.2.3.4.5, 1.3.6.1.4.1.311) is NOT mistaken for an IP. Validity / 999.x
# rejection is still done via ipaddress.ip_address().
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# IPv6 literal (compressed or full form). Requires a '::' or all 8 groups, so
# it does not match a bare 'h:m:s' time or a C++ 'a:b' scope fragment; every
# candidate is still validated by ipaddress.ip_address(). In CODE files the
# detector only runs inside string/comment zones, so this never touches actual
# C++ '::' scope-resolution tokens.
IPV6_PATTERN = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::"
    r")(?![\w:.])"
)

# Well-known public DNS — safe placeholders, kept (not flagged) like the doc IPs.
_KEEP_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,})\b"
)


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """A globally-routable address worth redacting.

    Uses ``ip.is_global`` as the primary test, which already keeps private
    (RFC1918), loopback, link-local, reserved, unspecified, CGNAT (RFC6598
    100.64.0.0/10), and the RFC5737/RFC3849 documentation ranges (all
    non-global). Multicast is excluded explicitly (it can be global) and the
    well-known public-DNS placeholders are kept.
    """
    if not ip.is_global:
        return False
    if ip.is_multicast:
        return False
    if str(ip) in _KEEP_IPS:
        return False
    return True


class EndpointDetector(Detector):
    """Detect internal domains and PUBLIC IPs (IPv4 + IPv6).

    Globally-routable IP addresses are deployment fingerprints and get flagged
    (HIGH). Private / loopback / reserved / CGNAT / documentation-range
    addresses are KEPT. ``keep`` exempts allowlisted domains/hosts (and
    specific IP literals).
    """

    def __init__(
        self,
        domain_list: list[str] | None = None,
        keep: set[str] | None = None,
    ) -> None:
        self.domain_list = {d.lower() for d in (domain_list or [])}
        self.keep = keep or set()

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        findings.extend(self._detect_public_ips(target))
        findings.extend(self._detect_internal_domains(target))
        return findings

    def _detect_public_ips(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for pattern in (IPV4_PATTERN, IPV6_PATTERN):
            for m in pattern.finditer(target.content):
                start, end = m.start(), m.end()
                if not self._in_zones(target, start, end):
                    continue
                value = m.group()
                if value in self.keep:
                    continue
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not _is_public_ip(ip):
                    continue
                line = target.content[:start].count("\n") + 1
                findings.append(
                    Finding(
                        detector="EndpointDetector",
                        category=Category.ENDPOINT,
                        severity=Severity.HIGH,
                        file_path=target.file_path,
                        line=line,
                        offset_start=start,
                        offset_end=end,
                        matched_value=value,
                    )
                )
        return findings

    def _detect_internal_domains(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for m in DOMAIN_PATTERN.finditer(target.content):
            domain = m.group().lower()
            start, end = m.start(), m.end()
            if not self._in_zones(target, start, end):
                continue
            if domain in self.keep or any(
                domain.endswith("." + k) for k in self.keep
            ):
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
