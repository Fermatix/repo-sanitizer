from __future__ import annotations

import re

from repo_sanitizer.buildsafe import contains_mask, is_template, luhn_ok
from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)
from repo_sanitizer.detectors.endpoint import _is_kept_url_host
from repo_sanitizer.rulepack import PIIPattern

# Connection-string / non-http URL endpoint patterns whose host the scrubber
# KEEPS when it is universal/private/localhost (see history_ops._mask_endpoint_url).
# The detector must agree — else a `redis://localhost` is flagged forever while the
# scrubber correctly leaves it, and the gate never reaches zero. basic_auth_in_url
# is deliberately ABSENT (it always carries credentials → always a leak).
_KEEPABLE_CONN_STRING_NAMES = frozenset({
    "db_connection_postgresql", "db_connection_mysql", "db_connection_mongodb",
    "db_connection_redis", "db_connection_amqp", "jdbc_url",
})
_CONN_HOST_RE = re.compile(r"^[a-z][\w+.\-]*://(?:[^/@\s]*@)?(\[[0-9A-Fa-f:.]+\]|[^/:\s?#]+)", re.IGNORECASE)


class RegexPIIDetector(Detector):
    """Detect PII using regex patterns from rulepack."""

    def __init__(self, patterns: list[PIIPattern], keep: set[str] | None = None) -> None:
        self.patterns = patterns
        self.keep = keep or set()

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        for pat in self.patterns:
            for m in pat.pattern.finditer(target.content):
                start, end = m.start(), m.end()
                if not self._in_zones(target, start, end):
                    continue
                value = m.group()
                # Idempotency: a structure-preserving mask keeps the pattern shape
                # (apiKey="REDACTED_<hash>", postgres://<hash>.example.invalid), so
                # skip a match that is already one of our placeholders — otherwise
                # the pattern re-fires forever and the gate never reaches zero.
                if contains_mask(value):
                    continue
                # A format-string / interpolation TEMPLATE (amqp://%s:%s@%s/%s,
                # ?token={{$t}}, postgres://${HOST}/db) is not a real endpoint /
                # secret and is deliberately left unmasked by the scrubber — so the
                # gate must not flag it either (it carries no identifying value).
                if is_template(value):
                    continue
                # A card-shaped match that fails Luhn is numeric DATA (a float /
                # Unity fileID / model weight), not a card — not masked, not gated.
                if pat.name == "credit_card" and not luhn_ok(value):
                    continue
                # A connection string to a KEPT host (localhost / private IP /
                # generic service / allowlisted) is left intact by the scrubber, so
                # don't flag it either (a `redis://localhost` example is not a leak).
                if pat.name in _KEEPABLE_CONN_STRING_NAMES and self._conn_host_kept(value):
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

    def _conn_host_kept(self, value: str) -> bool:
        """True if the connection string's host is one the scrubber keeps."""
        m = _CONN_HOST_RE.match(value)
        if not m:
            return False
        return _is_kept_url_host(m.group(1).strip("[]"), self.keep)

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)
