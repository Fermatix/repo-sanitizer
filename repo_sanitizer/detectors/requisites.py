"""Co-located Russian requisites (2026-09-03, lord-of-the-repos plan 5b.3).

A requisites record is a CLUSTER: ИНН, КПП, ОГРН, ОКПО, БИК, р/с, к/с, лицевой счёт, КЛАДР code — one per
line, or one per key of a dict / JSON object / Person(...) fixture. ``RuLegalIdDetector`` already finds the
checksum-valid ИНН / ОГРН anchors; the audit rounds then kept finding, by hand, the siblings on the
neighbouring lines (КПП 9 digits, accounts 20 digits, лицевой счёт 8–20) — 29 of the 60 legal ids the LLM
rounds reported were exactly that: half-redacted records. Those siblings have no checksum, so on their
own they are far too false-positive-prone; ANCHORED to a valid ИНН/ОГРН in the same file they are not.

Rule: the file must contain ≥ 1 checksum-valid ИНН/ОГРН. Then flag
  * any 9- or 20-digit run within ± WINDOW lines of an anchor (КПП / БИК / р/с / к/с shapes), and
  * any 8–20-digit run whose line carries a requisites KEY (inn, kpp, ogrn, okpo, bik, kladr, account,
    schet, лицевой счёт, р/с, к/с, …) anywhere in the file.
Runs that are themselves valid legal ids are left to ``RuLegalIdDetector``. Zone-free, like the anchor
detector (the misses were bare ints in .py fixtures and HTML text in .php).
"""
from __future__ import annotations

import re
from bisect import bisect_right

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)
from repo_sanitizer.detectors.legal_id import _DIGIT_RUN, is_valid_ru_legal_id

WINDOW = 6
_RUN = re.compile(r"(?<![\w.])(\d{8,20})(?![\w.])")
_KEY = re.compile(
    r"(?i)(?<![A-Za-zА-Яа-яЁё])(?:inn|kpp|ogrn(?:ip)?|okpo|oktmo|okato|bik|bic|kladr|fias|"
    r"account(?:_?(?:no|num|number|id))?|acc(?:_?no)?|schet|r[_\-]?s|k[_\-]?s|ls|"
    r"инн|кпп|огрн(?:ип)?|окпо|октмо|окато|бик|кладр|фиас|лицев\w*|л/с|р/с|к/с|сч[её]т\w*|расч\w*|корр\w*)"
    r"(?![A-Za-zА-Яа-яЁё])"
)


_SEP = re.compile(r"[\s\"':=>\-№\[\(]*")


class RuRequisitesDetector(Detector):
    """Flag the label-less siblings of a checksum-valid ИНН / ОГРН inside a requisites record."""

    def detect(self, target: ScanTarget) -> list[Finding]:
        content = target.content
        anchors = [m.start(1) for m in _DIGIT_RUN.finditer(content) if is_valid_ru_legal_id(m.group(1))]
        if not anchors:
            return []
        line_starts = [0] + [i + 1 for i, c in enumerate(content) if c == "\n"]
        # Index keys once: rescanning every numeric value's line prefix is
        # quadratic on minified JSON. A key cannot span a candidate number:
        # _RUN requires a non-word boundary before the number.
        key_spans = [(m.start(), m.end()) for m in _KEY.finditer(content)]
        key_ends = [end for _, end in key_spans]

        def line_of(pos: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:                       # bisect: index of the last line start <= pos
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= pos:
                    lo = mid
                else:
                    hi = mid - 1
            return lo

        anchor_lines = sorted({line_of(a) for a in anchors})
        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()
        for m in _RUN.finditer(content):
            value = m.group(1)
            start, end = m.start(1), m.end(1)
            if is_valid_ru_legal_id(value) or (start, end) in seen:
                continue
            ln = line_of(start)
            near = any(abs(ln - a) <= WINDOW for a in anchor_lines)
            # Only the nearest preceding key on this line may vouch for the
            # number, and only when separators occur between the two. Passing
            # bounds to fullmatch also avoids copying a potentially huge prefix.
            key_index = bisect_right(key_ends, start) - 1
            keyed = (
                key_index >= 0
                and key_spans[key_index][0] >= line_starts[ln]
                and _SEP.fullmatch(content, key_ends[key_index], start) is not None
            )
            if not ((near and len(value) in (9, 20)) or keyed):
                continue
            seen.add((start, end))
            findings.append(
                Finding(
                    detector="RuRequisitesDetector",
                    category=Category.PII,
                    severity=Severity.HIGH,
                    file_path=target.file_path,
                    line=ln + 1,
                    offset_start=start,
                    offset_end=end,
                    matched_value=value,
                )
            )
        return findings
