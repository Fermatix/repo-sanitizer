"""Structural brand detection — brands that survive in code *structure*.

The zone-restricted DictionaryDetector only sees brands inside string literals
and comments. Brands also leak through:

* **path components** — a dir ``extyl/`` or a file ``ExtylProfile.php`` (4a), and
* **code identifiers / package-namespace declarations** — ``ExtylProfile``,
  ``package ru.extyl.app`` (4b).

These are **detection-only**: the findings GATE (so the re-scan stops silently
passing) but are never rewritten — the coherent ``brand → AcmeN`` rename is
Pass-2. Both passes share one Aho-Corasick automaton built from the
(variant-expanded, keep-filtered) brand terms.
"""
from __future__ import annotations

import bisect

import ahocorasick

from repo_sanitizer.detectors.base import (
    Category,
    Finding,
    Severity,
    Zone,
)


class BrandMatcher:
    """Case-insensitive substring matcher over (keep-filtered) brand terms."""

    def __init__(self, terms: list[str], keep: set[str] | None = None) -> None:
        self.keep = keep or set()
        self.automaton = ahocorasick.Automaton()
        n = 0
        for term in terms:
            key = (term or "").lower()
            if not key or key in self.keep:
                continue
            self.automaton.add_word(key, (len(key), term))
            n += 1
        if n:
            self.automaton.make_automaton()
        self._has_terms = n > 0

    @property
    def has_terms(self) -> bool:
        return self._has_terms

    def find(self, text: str) -> list[tuple[int, int, str]]:
        """Return (start, end, original_substring) char spans for every match."""
        if not self._has_terms or not text:
            return []
        # keep terms are already excluded from the automaton at build time, so
        # no match can be a kept term — no per-match keep re-check is needed.
        results = []
        lowered = text.lower()
        for end_idx, (term_len, _term) in self.automaton.iter(lowered):
            start = end_idx - term_len + 1
            end = end_idx + 1
            results.append((start, end, text[start:end]))
        return results


class _SpanIndex:
    """Membership test over merged, non-overlapping, sorted zones."""

    def __init__(self, zones: list[Zone] | None) -> None:
        ordered = sorted(zones or [], key=lambda z: z.start)
        self._starts = [z.start for z in ordered]
        self._ends = [z.end for z in ordered]

    def contains(self, start: int, end: int) -> bool:
        if not self._starts:
            return False
        i = bisect.bisect_right(self._starts, start) - 1
        if i < 0:
            return False
        return self._starts[i] <= start and end <= self._ends[i]


class BrandPathDetector:
    """4a — brands inside file/dir path components (language-independent)."""

    def __init__(self, matcher: BrandMatcher) -> None:
        self.matcher = matcher

    def detect_inventory(self, inventory) -> list[Finding]:
        """Scan every inventory item's path. A brand dir/file name leaks
        regardless of the file's SCAN/DELETE/SKIP action, so all items are
        checked. Findings are deduped by (path-prefix-through-component, term):
        one brand directory does not produce a finding for every file beneath
        it, but the SAME brand component at two DISTINCT locations
        (a/extyl, b/extyl) is reported once each rather than collapsed.
        """
        if not self.matcher.has_terms:
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for item in inventory:
            path = item.path
            offset = 0
            for component in path.split("/"):
                # Case-sensitive prefix: src/Extyl and src/extyl are distinct
                # directories on a case-sensitive filesystem and each leak.
                prefix = path[: offset + len(component)]
                for start, end, value in self.matcher.find(component):
                    key = (prefix, value.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            detector="BrandPathDetector",
                            category=Category.BRAND_PATH,
                            severity=Severity.HIGH,
                            file_path=item.path,
                            line=0,
                            offset_start=offset + start,
                            offset_end=offset + end,
                            matched_value=value,
                        )
                    )
                offset += len(component) + 1  # +1 for the '/' separator
        return findings


class BrandStructuralDetector:
    """4b — brands inside code identifiers / package-namespace declarations.

    Runs the brand automaton over the WHOLE file once, then categorizes each
    match by where it lands:

    * inside a string/comment zone → **skipped** (that is DictionaryDetector's
      job — keeps the two passes from double-reporting the same literal),
    * inside a package/namespace/import declaration → ``PACKAGE_NAMESPACE``,
    * anywhere else in code (necessarily part of an identifier — keywords and
      punctuation cannot contain a multi-character brand) → ``BRAND_IDENTIFIER``.
    """

    def __init__(self, matcher: BrandMatcher) -> None:
        self.matcher = matcher

    def detect(
        self,
        file_path: str,
        content: str,
        exclude_zones: list[Zone] | None,
        package_spans: list[Zone] | None,
    ) -> list[Finding]:
        if not self.matcher.has_terms:
            return []
        matches = self.matcher.find(content)
        if not matches:
            return []
        excl = _SpanIndex(exclude_zones)
        pkg = _SpanIndex(package_spans)
        findings: list[Finding] = []
        for start, end, value in matches:
            if excl.contains(start, end):
                continue  # string/comment literal — DictionaryDetector handles it
            category = (
                Category.PACKAGE_NAMESPACE
                if pkg.contains(start, end)
                else Category.BRAND_IDENTIFIER
            )
            line = content[:start].count("\n") + 1
            findings.append(
                Finding(
                    detector="BrandStructuralDetector",
                    category=category,
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line=line,
                    offset_start=start,
                    offset_end=end,
                    matched_value=value,
                )
            )
        return findings
