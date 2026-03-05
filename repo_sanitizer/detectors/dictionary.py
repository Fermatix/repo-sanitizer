from __future__ import annotations

import ahocorasick

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)


class DictionaryDetector(Detector):
    """Detect corporate dictionary terms using Aho-Corasick."""

    def __init__(self, dictionaries: dict[str, list[str]]) -> None:
        self.automaton = ahocorasick.Automaton()
        self._terms: dict[str, str] = {}
        idx = 0
        for dict_name, terms in dictionaries.items():
            for term in terms:
                if not term:
                    continue
                key = term.lower()
                self.automaton.add_word(key, (idx, term, dict_name))
                self._terms[key] = dict_name
                idx += 1
        if idx > 0:
            self.automaton.make_automaton()
        self._has_terms = idx > 0

    def detect(self, target: ScanTarget) -> list[Finding]:
        if not self._has_terms:
            return []
        findings = []
        content_lower = target.content.lower()
        for end_idx, (_, term, dict_name) in self.automaton.iter(content_lower):
            start = end_idx - len(term) + 1
            end = end_idx + 1
            if not self._in_zones(target, start, end):
                continue
            original = target.content[start:end]
            line = target.content[:start].count("\n") + 1
            findings.append(
                Finding(
                    detector="DictionaryDetector",
                    category=Category.DICTIONARY,
                    severity=Severity.HIGH,
                    file_path=target.file_path,
                    line=line,
                    offset_start=start,
                    offset_end=end,
                    matched_value=original,
                )
            )
        return findings

    @staticmethod
    def _in_zones(target: ScanTarget, start: int, end: int) -> bool:
        if not target.is_zoned:
            return True
        return any(z.start <= start and end <= z.end for z in target.zones)
