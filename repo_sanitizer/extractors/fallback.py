from __future__ import annotations

import re

from repo_sanitizer.detectors.base import Zone


class FallbackExtractor:
    """Regex-based comment extraction as a fallback when tree-sitter is unavailable."""

    def __init__(self, comment_patterns: list[str] | None = None) -> None:
        default_patterns = [r"#.*$", r"//.*$", r"--.*$"]
        patterns = comment_patterns if comment_patterns else default_patterns
        self._patterns = [re.compile(p, re.MULTILINE) for p in patterns]

    def extract_zones(self, content: str) -> list[Zone]:
        zones = []
        for pattern in self._patterns:
            for m in pattern.finditer(content):
                zones.append(Zone(start=m.start(), end=m.end()))
        zones.sort(key=lambda z: z.start)
        return self._merge(zones)

    @staticmethod
    def _merge(zones: list[Zone]) -> list[Zone]:
        if not zones:
            return zones
        merged = [zones[0]]
        for z in zones[1:]:
            if z.start <= merged[-1].end:
                merged[-1] = Zone(
                    start=merged[-1].start, end=max(merged[-1].end, z.end)
                )
            else:
                merged.append(z)
        return merged
