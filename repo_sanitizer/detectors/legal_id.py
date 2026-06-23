"""Checksum-validated Russian legal-entity identifiers (ИНН / ОГРН).

The regex `inn_ru` / `ogrn_ru` patterns are LABEL-anchored (they need an
`ИНН`/`ОГРН` prefix). Real leaks repeatedly put a valid ОГРН/ИНН on a line
*separate* from its label (a footer, a `requisites` block, a `Person(...)`
fixture) — invisible to the label-anchored regex. A bare digit-run is far too
false-positive-prone to flag on length alone, so this detector validates the
official control-digit CHECKSUM (and, for the 13-digit ОГРН that collides with
unix-millisecond timestamps, a plausible registration-year field) before
flagging. That keeps the false-positive rate near zero while catching the
label-less identifiers the audits keep finding by hand.
"""
from __future__ import annotations

import re

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)

# A run of exactly 10, 12, 13 or 15 digits, not glued to other digits/word chars
# or a decimal point (so it is not the head of a longer number / version / float).
_DIGIT_RUN = re.compile(r"(?<![\w.])(\d{10}|\d{12}|\d{13}|\d{15})(?![\w.])")


def _inn10_valid(d: str) -> bool:
    coef = (2, 4, 10, 3, 5, 9, 4, 6, 8)
    ctrl = sum(int(d[i]) * coef[i] for i in range(9)) % 11 % 10
    return ctrl == int(d[9])


def _inn12_valid(d: str) -> bool:
    c1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    c2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    n1 = sum(int(d[i]) * c1[i] for i in range(10)) % 11 % 10
    n2 = sum(int(d[i]) * c2[i] for i in range(11)) % 11 % 10
    return n1 == int(d[10]) and n2 == int(d[11])


def _ogrn_year_plausible(d: str) -> bool:
    """ОГРН digits[1:3] encode the last two digits of the registration year.
    Valid Russian registrations run 1993-1999 and 2001..~now, so a value like a
    unix-ms timestamp's `71` (from 17188…) is rejected. Kills the timestamp FP."""
    yy = int(d[1:3])
    return 1 <= yy <= 35 or 93 <= yy <= 99


def _ogrn13_valid(d: str) -> bool:
    # control = (first 12 digits as int) mod 11, then mod 10
    return (int(d[:12]) % 11) % 10 == int(d[12]) and _ogrn_year_plausible(d)


def _ogrn15_valid(d: str) -> bool:
    # ОГРНИП: control = (first 14 digits as int) mod 13, then mod 10
    return (int(d[:14]) % 13) % 10 == int(d[14]) and _ogrn_year_plausible(d)


def is_valid_ru_legal_id(value: str) -> bool:
    """True if ``value`` is a checksum-valid ИНН (10/12) or ОГРН/ОГРНИП (13/15)."""
    if not value.isdigit():
        return False
    # All-same-digit runs (0000000000, 1111111111) satisfy the modular checksum
    # but are obvious placeholders, not real identifiers.
    if len(set(value)) == 1:
        return False
    return {
        10: _inn10_valid,
        12: _inn12_valid,
        13: _ogrn13_valid,
        15: _ogrn15_valid,
    }.get(len(value), lambda _d: False)(value)


class RuLegalIdDetector(Detector):
    """Flag checksum-valid Russian ИНН / ОГРН appearing WITHOUT a label."""

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for m in _DIGIT_RUN.finditer(target.content):
            start, end = m.start(1), m.end(1)
            if not self._in_zones(target, start, end):
                continue
            value = m.group(1)
            if not is_valid_ru_legal_id(value):
                continue
            line = target.content[:start].count("\n") + 1
            findings.append(
                Finding(
                    detector="RuLegalIdDetector",
                    category=Category.PII,
                    severity=Severity.HIGH,
                    file_path=target.file_path,
                    line=line,
                    offset_start=start,
                    offset_end=end,
                    matched_value=value,
                )
            )
        return findings

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)
