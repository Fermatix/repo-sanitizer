from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from repo_sanitizer.detectors.base import Finding


class FileCategory(str, Enum):
    CODE = "code"
    CONFIG = "config"
    DOCS = "docs"
    BINARY = "binary"


class FileAction(str, Enum):
    SCAN = "SCAN"
    DELETE = "DELETE"
    SKIP = "SKIP"


@dataclass
class InventoryItem:
    path: str
    size: int
    mime: str
    category: FileCategory
    action: FileAction
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "mime": self.mime,
            "category": self.category.value,
            "action": self.action.value,
            "reason": self.reason,
        }


@dataclass
class RunContext:
    salt: bytes
    work_dir: Path
    out_dir: Path
    artifacts_dir: Path
    rulepack_path: Path
    rulepack: object = None  # loaded Rulepack
    inventory: list[InventoryItem] = field(default_factory=list)
    pre_findings: list[Finding] = field(default_factory=list)
    post_findings: list[Finding] = field(default_factory=list)
    history_pre_findings: list[Finding] = field(default_factory=list)
    history_post_findings: list[Finding] = field(default_factory=list)
    history_blob_pre_findings: list[Finding] = field(default_factory=list)
    history_blob_post_findings: list[Finding] = field(default_factory=list)
    redaction_manifest: list[dict] = field(default_factory=list)
    timings: dict = field(default_factory=dict)
    rev: str = "HEAD"
    max_file_mb: int = 20
    history_since: Optional[str] = None
    history_until: Optional[str] = None
    ner_service_url: Optional[str] = None  # if set, NERDetector calls this HTTP service

    @classmethod
    def create(
        cls,
        source: str,
        out_dir: Path,
        rulepack_path: Path,
        salt_env: str = "REPO_SANITIZER_SALT",
        rev: str = "HEAD",
        max_file_mb: int = 20,
        history_since: Optional[str] = None,
        history_until: Optional[str] = None,
    ) -> RunContext:
        salt_value = os.environ.get(salt_env, "")
        if not salt_value:
            raise ValueError(
                f"Environment variable '{salt_env}' is not set or empty. "
                "Salt is required for deterministic anonymization."
            )
        out = Path(out_dir).expanduser().resolve()
        work = out / "work"
        artifacts = out / "artifacts"
        work.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        (out / "output").mkdir(parents=True, exist_ok=True)
        return cls(
            salt=salt_value.encode(),
            work_dir=work,
            out_dir=out,
            artifacts_dir=artifacts,
            rulepack_path=Path(rulepack_path).expanduser().resolve(),
            rev=rev,
            max_file_mb=max_file_mb,
            history_since=history_since,
            history_until=history_until,
        )
