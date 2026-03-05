from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class PIIPattern:
    name: str
    pattern: re.Pattern
    category: str
    severity: str


@dataclass
class ExtractorLanguage:
    id: str
    grammar_package: str
    file_extensions: list[str]
    extract_zones: list[str]


@dataclass
class ExtractorConfig:
    languages: list[ExtractorLanguage] = field(default_factory=list)
    redact_string_literals: bool = True
    min_string_length: int = 4
    on_parse_error: str = "fallback"
    fallback_enabled: bool = True
    fallback_comment_patterns: list[str] = field(default_factory=list)


@dataclass
class NERConfig:
    model: str = "Davlan/bert-base-multilingual-cased-ner-hrl"
    min_score: float = 0.7
    entity_types: list[str] = field(default_factory=lambda: ["PER", "ORG"])
    device: str = "cpu"


@dataclass
class Rulepack:
    path: Path
    version: str
    deny_globs: list[str] = field(default_factory=list)
    allow_suffixes: list[str] = field(default_factory=list)
    binary_deny_extensions: list[str] = field(default_factory=list)
    binary_allow_extensions: list[str] = field(default_factory=list)
    max_file_mb: int = 20
    ner: NERConfig = field(default_factory=NERConfig)
    extractor: ExtractorConfig = field(default_factory=ExtractorConfig)
    pii_patterns: list[PIIPattern] = field(default_factory=list)
    dictionaries: dict[str, list[str]] = field(default_factory=dict)


def load_rulepack(path: Path) -> Rulepack:
    path = Path(path)
    if not path.is_dir():
        raise FileNotFoundError(f"Rulepack directory not found: {path}")

    version_file = path / "VERSION"
    if not version_file.exists():
        raise FileNotFoundError(
            f"VERSION file not found in rulepack: {path}. "
            "Every rulepack must contain a VERSION file."
        )
    version = version_file.read_text().strip()

    policies = _load_yaml(path / "policies.yaml")
    ner_cfg = policies.get("ner", {})
    ner = NERConfig(
        model=ner_cfg.get("model", NERConfig.model),
        min_score=ner_cfg.get("min_score", NERConfig.min_score),
        entity_types=ner_cfg.get("entity_types", ["PER", "ORG"]),
        device=ner_cfg.get("device", NERConfig.device),
    )

    extractor = _load_extractor_config(path / "extractors.yaml")
    pii_patterns = _load_pii_patterns(path / "regex" / "pii_patterns.yaml")
    dictionaries = _load_dictionaries(path / "dict")

    return Rulepack(
        path=path,
        version=version,
        deny_globs=policies.get("deny_globs", []),
        allow_suffixes=policies.get("allow_suffixes", []),
        binary_deny_extensions=policies.get("binary_deny_extensions", []),
        binary_allow_extensions=policies.get("binary_allow_extensions", []),
        max_file_mb=policies.get("max_file_mb", 20),
        ner=ner,
        extractor=extractor,
        pii_patterns=pii_patterns,
        dictionaries=dictionaries,
    )


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def _load_extractor_config(path: Path) -> ExtractorConfig:
    data = _load_yaml(path)
    if not data:
        return ExtractorConfig()

    ts = data.get("treesitter", {})
    languages = []
    for lang in ts.get("languages", []):
        if "grammar_package" not in lang:
            raise ValueError(
                f"Missing 'grammar_package' for language '{lang.get('id', '?')}' "
                f"in {path}. Each language entry must specify a grammar_package."
            )
        languages.append(
            ExtractorLanguage(
                id=lang["id"],
                grammar_package=lang["grammar_package"],
                file_extensions=lang.get("file_extensions", []),
                extract_zones=lang.get("extract_zones", []),
            )
        )

    zone_policy = ts.get("zone_policy", {})
    fb = data.get("fallback_extractor", {})
    fb_patterns = [p["pattern"] for p in fb.get("comment_patterns", [])]

    return ExtractorConfig(
        languages=languages,
        redact_string_literals=zone_policy.get("redact_string_literals", True),
        min_string_length=zone_policy.get("min_string_length", 4),
        on_parse_error=ts.get("on_parse_error", "fallback"),
        fallback_enabled=fb.get("enabled", True),
        fallback_comment_patterns=fb_patterns,
    )


def _load_pii_patterns(path: Path) -> list[PIIPattern]:
    data = _load_yaml(path)
    patterns = []
    for item in data.get("patterns", []):
        patterns.append(
            PIIPattern(
                name=item["name"],
                pattern=re.compile(item["pattern"]),
                category=item.get("category", "PII"),
                severity=item.get("severity", "HIGH"),
            )
        )
    return patterns


def _load_dictionaries(path: Path) -> dict[str, list[str]]:
    result = {}
    if not path.is_dir():
        return result
    for txt_file in path.glob("*.txt"):
        name = txt_file.stem
        lines = [
            line.strip()
            for line in txt_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        result[name] = lines
    return result
