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
