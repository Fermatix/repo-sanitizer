from __future__ import annotations

import hmac
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SECRET = "SECRET"
    PII = "PII"
    ORG_NAME = "ORG_NAME"
    DICTIONARY = "DICTIONARY"
    ENDPOINT = "ENDPOINT"
    # Brand findings that survive in code structure rather than literals/comments.
    # Detected + gated by Pass-1, but NEVER rewritten here (see BRAND_DETECTION_ONLY).
    BRAND_IDENTIFIER = "BRAND_IDENTIFIER"      # brand inside a code identifier (ExtylProfile)
    BRAND_PATH = "BRAND_PATH"                  # brand inside a file/dir path component
    PACKAGE_NAMESPACE = "PACKAGE_NAMESPACE"    # brand inside package/namespace/import decl


# Categories that Pass-1 DETECTS and GATES but must NOT rewrite. The coherent
# brand → AcmeN map is applied once, in Pass-2 (Claude + codex second look), so
# the same brand never receives two different deterministic masks. Consequently
# the brand gates are intentionally RED after Pass-1 — they ARE the worklist and
# only reach zero after Pass-2's rename + a re-scan. (SECRET / PII / ENDPOINT /
# person-PER findings stay rewrite-in-place; they are not brands.)
BRAND_DETECTION_ONLY: frozenset[Category] = frozenset(
    {
        Category.DICTIONARY,
        Category.ORG_NAME,
        Category.BRAND_IDENTIFIER,
        Category.BRAND_PATH,
        Category.PACKAGE_NAMESPACE,
    }
)


def is_detection_only(finding: "Finding") -> bool:
    """True if a finding is a brand worklist item (gated, never rewritten).

    Detector-aware: DICTIONARY / ORG_NAME are brands ONLY when they come from
    the brand detectors. The regex PII rulepack also categorizes some matches
    as DICTIONARY (jira_ticket / github_issue_ref / uuid) — those are internal
    IDs, not brands, and must still be redacted. The three structural
    categories are only ever produced by the brand path/identifier detectors.
    """
    cat = finding.category
    if cat in (
        Category.BRAND_IDENTIFIER,
        Category.BRAND_PATH,
        Category.PACKAGE_NAMESPACE,
    ):
        return True
    if cat == Category.DICTIONARY:
        return finding.detector == "DictionaryDetector"
    if cat == Category.ORG_NAME:
        return finding.detector == "NERDetector"
    return False


@dataclass
class Finding:
    detector: str
    category: Category
    severity: Severity
    file_path: str
    line: int
    offset_start: int
    offset_end: int
    matched_value: str = field(repr=False)
    value_hash: str = ""

    def compute_hash(self, salt: bytes) -> None:
        self.value_hash = hmac.new(
            salt, self.matched_value.encode(), "sha256"
        ).hexdigest()[:12]

    def to_report(self) -> dict:
        return {
            "detector": self.detector,
            "category": self.category.value,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line": self.line,
            "offset_start": self.offset_start,
            "offset_end": self.offset_end,
            "value_hash": self.value_hash,
        }


@dataclass
class Zone:
    start: int
    end: int


@dataclass
class ScanTarget:
    file_path: str
    content: str
    zones: Optional[list[Zone]] = None

    @property
    def is_zoned(self) -> bool:
        return self.zones is not None


class Detector(ABC):
    @abstractmethod
    def detect(self, target: ScanTarget) -> list[Finding]:
        ...
