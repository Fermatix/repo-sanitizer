from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from repo_sanitizer.detectors.base import Zone
from repo_sanitizer.rulepack import ExtractorConfig, ExtractorLanguage

logger = logging.getLogger(__name__)


@dataclass
class GrammarStatus:
    language_id: str
    grammar_package: str
    installed: bool
    missing_attribute: str | None = None  # set when pkg installed but fn missing


def check_grammar_packages(config: ExtractorConfig) -> list[GrammarStatus]:
    """Check which grammar packages from the extractor config are installed."""
    statuses = []
    for lang in config.languages:
        pkg_name = lang.grammar_package.replace("-", "_")
        try:
            mod = importlib.import_module(pkg_name)
            fn_name = _GRAMMAR_FN_OVERRIDES.get(lang.id, "language")
            if not hasattr(mod, fn_name):
                statuses.append(
                    GrammarStatus(
                        language_id=lang.id,
                        grammar_package=lang.grammar_package,
                        installed=True,
                        missing_attribute=fn_name,
                    )
                )
            else:
                statuses.append(
                    GrammarStatus(
                        language_id=lang.id,
                        grammar_package=lang.grammar_package,
                        installed=True,
                    )
                )
        except ImportError:
            statuses.append(
                GrammarStatus(
                    language_id=lang.id,
                    grammar_package=lang.grammar_package,
                    installed=False,
                )
            )
    return statuses

# Some grammar packages don't export the generic `language()` function.
# Map language id → actual exported function name.
_GRAMMAR_FN_OVERRIDES: dict[str, str] = {
    "typescript": "language_typescript",
    "tsx": "language_tsx",
}

NODE_TYPE_MAP = {
    "python": {
        "comment_line": ["comment"],
        "comment_block": ["comment"],
        "docstring": ["string", "concatenated_string"],
        "string_literal": ["string", "concatenated_string"],
    },
    "javascript": {
        "comment_line": ["comment"],
        "comment_block": ["comment"],
        "string_literal": ["string", "string_fragment"],
        "template_literal": ["template_string"],
    },
    "typescript": {
        "comment_line": ["comment"],
        "comment_block": ["comment"],
        "string_literal": ["string", "string_fragment"],
        "template_literal": ["template_string"],
    },
}


def _is_docstring(node, source_bytes: bytes) -> bool:
    if node.type != "string" and node.type != "expression_statement":
        return False
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "expression_statement":
        gp = parent.parent
        if gp and gp.type in ("module", "function_definition", "class_definition"):
            children = [
                c
                for c in gp.children
                if c.type not in ("decorator", "comment", "newline")
            ]
            for i, c in enumerate(children):
                if c.type == "block":
                    block_children = list(c.children)
                    if block_children and block_children[0].id == parent.id:
                        return True
                if c.id == parent.id and i == 0:
                    return True
    return False


class TreeSitterExtractor:
    """Extract scannable zones from source code using tree-sitter."""

    def __init__(self, config: ExtractorConfig) -> None:
        self.config = config
        self._parsers: dict[str, tuple] = {}
        self._ext_map: dict[str, ExtractorLanguage] = {}
        for lang in config.languages:
            for ext in lang.file_extensions:
                self._ext_map[ext] = lang

    def get_language_for_file(self, file_path: str) -> Optional[ExtractorLanguage]:
        ext = Path(file_path).suffix.lower()
        return self._ext_map.get(ext)

    def _get_parser(self, lang: ExtractorLanguage):
        if lang.id in self._parsers:
            return self._parsers[lang.id]
        try:
            import tree_sitter
        except ImportError:
            raise RuntimeError(
                "tree-sitter is not installed. Install with: pip install tree-sitter"
            )
        pkg_name = lang.grammar_package.replace("-", "_")
        try:
            grammar_module = importlib.import_module(pkg_name)
        except ImportError:
            raise RuntimeError(
                f"Grammar package '{lang.grammar_package}' is not installed. "
                f"Install with: pip install {lang.grammar_package}"
            )
        fn_name = _GRAMMAR_FN_OVERRIDES.get(lang.id, "language")
        if not hasattr(grammar_module, fn_name):
            raise RuntimeError(
                f"Grammar package '{lang.grammar_package}' has no attribute '{fn_name}'. "
                f"Available: {[a for a in dir(grammar_module) if not a.startswith('_')]}"
            )
        ts_language = tree_sitter.Language(getattr(grammar_module, fn_name)())
        parser = tree_sitter.Parser(ts_language)
        self._parsers[lang.id] = (parser, ts_language, lang)
        return self._parsers[lang.id]

    def extract_zones(self, file_path: str, content: str) -> Optional[list[Zone]]:
        lang = self.get_language_for_file(file_path)
        if lang is None:
            return None
        try:
            parser, ts_language, _ = self._get_parser(lang)
        except RuntimeError as e:
            if self.config.on_parse_error == "fail":
                raise
            if self.config.on_parse_error == "skip":
                logger.warning("Skipping %s: %s", file_path, e)
                return []
            logger.warning("Falling back for %s: %s", file_path, e)
            return None

        source_bytes = content.encode("utf-8")
        try:
            tree = parser.parse(source_bytes)
        except Exception as e:
            if self.config.on_parse_error == "fail":
                raise RuntimeError(f"Tree-sitter parse error for {file_path}: {e}")
            if self.config.on_parse_error == "skip":
                logger.warning("Skipping %s due to parse error: %s", file_path, e)
                return []
            logger.warning("Falling back for %s due to parse error: %s", file_path, e)
            return None

        wanted_node_types = set()
        is_python = lang.id == "python"
        has_docstring = "docstring" in lang.extract_zones
        has_string = "string_literal" in lang.extract_zones

        type_map = NODE_TYPE_MAP.get(lang.id, {})
        for zone_type in lang.extract_zones:
            if zone_type == "docstring" and is_python:
                continue
            for nt in type_map.get(zone_type, []):
                wanted_node_types.add(nt)

        zones = []
        self._walk_tree(
            tree.root_node,
            source_bytes,
            wanted_node_types,
            zones,
            is_python,
            has_docstring,
            has_string,
        )

        if not self.config.redact_string_literals:
            zones = [z for z in zones if z.end - z.start >= 0]

        zones = self._filter_min_length(zones)
        zones = self._merge_zones(zones)
        return zones

    def _walk_tree(
        self,
        node,
        source_bytes: bytes,
        wanted_types: set[str],
        zones: list[Zone],
        is_python: bool,
        has_docstring: bool,
        has_string: bool,
    ) -> None:
        if node.type in wanted_types:
            if node.type == "comment":
                zones.append(Zone(start=node.start_byte, end=node.end_byte))
            elif is_python and node.type in ("string", "concatenated_string"):
                is_doc = _is_docstring(node, source_bytes)
                if is_doc and has_docstring:
                    zones.append(Zone(start=node.start_byte, end=node.end_byte))
                elif not is_doc and has_string and self.config.redact_string_literals:
                    if node.end_byte - node.start_byte >= self.config.min_string_length:
                        zones.append(Zone(start=node.start_byte, end=node.end_byte))
            else:
                if node.end_byte - node.start_byte >= self.config.min_string_length:
                    zones.append(Zone(start=node.start_byte, end=node.end_byte))

        for child in node.children:
            self._walk_tree(
                child,
                source_bytes,
                wanted_types,
                zones,
                is_python,
                has_docstring,
                has_string,
            )

    def _filter_min_length(self, zones: list[Zone]) -> list[Zone]:
        return [
            z
            for z in zones
            if z.end - z.start >= self.config.min_string_length or z.end - z.start > 0
        ]

    @staticmethod
    def _merge_zones(zones: list[Zone]) -> list[Zone]:
        if not zones:
            return zones
        zones.sort(key=lambda z: z.start)
        merged = [zones[0]]
        for z in zones[1:]:
            if z.start <= merged[-1].end:
                merged[-1] = Zone(
                    start=merged[-1].start, end=max(merged[-1].end, z.end)
                )
            else:
                merged.append(z)
        return merged
