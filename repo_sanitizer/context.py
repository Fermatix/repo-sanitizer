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
    # Parse-validity (path → bool) of every structured config in the ORIGINAL tree,
    # snapshotted before redaction. The PARSEABLE_CONFIGS build-smoke gate re-checks
    # the rewritten tree and fails on any valid→invalid regression (a redaction that
    # broke a JSON/YAML/XML/csproj/TOML file).
    config_parse_pre: dict = field(default_factory=dict)
    timings: dict = field(default_factory=dict)
    # Branch topology captured at intake (steps/fetch.py) and the final ref set
    # produced by the ref-reconcile step (steps/ref_reconcile.py). intake_branch_tips
    # maps every local branch NAME present after intake → its tip SHA (the
    # pre-rewrite tip, used to look the rewritten tip up in filter-repo's
    # commit-map). branch_rename_map maps each intake branch name → its final
    # scrubbed slug (or None if it pruned to nothing). output_branches /
    # output_default_branch are the shipped head slugs + HEAD.
    intake_branch_tips: dict = field(default_factory=dict)     # {name: tip_sha}
    intake_default_branch: str = ""                            # default branch at intake
    branch_rename_map: dict = field(default_factory=dict)      # {intake_name: slug|None}
    output_branches: list = field(default_factory=list)        # final head slugs
    output_default_branch: str = ""                            # HEAD target slug
    rev: str = "HEAD"
    max_file_mb: int = 20
    history_since: Optional[str] = None
    history_until: Optional[str] = None
    ner_service_url: Optional[str] = None  # if set, NERDetector calls this HTTP service
    # Where the (expensive, CPU-bound) NER model runs:
    #   "head" — working tree at --rev only (default; fast, the "like before" path)
    #   "all"  — also over commit metadata + every history blob (slow, GPU-class)
    #   "off"  — never load NER at all (fastest; relies on dict/regex + Pass-2 audit)
    ner_scope: str = "head"

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
        ner_service_url: Optional[str] = None,
        ner_scope: str = "head",
    ) -> RunContext:
        salt_value = os.environ.get(salt_env, "")
        if not salt_value:
            raise ValueError(
                f"Environment variable '{salt_env}' is not set or empty. "
                "Salt is required for deterministic anonymization."
            )
        if ner_scope not in ("head", "all", "off"):
            raise ValueError(
                f"Invalid ner_scope {ner_scope!r}; expected one of head|all|off."
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
            ner_service_url=ner_service_url,
            ner_scope=ner_scope,
        )
