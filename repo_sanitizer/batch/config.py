from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml


@dataclass
class GitLabConfig:
    url: str
    token_env: str
    source_group: str
    delivery_group: str
    clone_depth: int = 0


@dataclass
class ScopeConfig:
    """Which repos to process.

    Priority (highest first): repos > partners > all.
    """
    all: bool = False
    partners: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)


@dataclass
class ProcessingConfig:
    workers: int = 8
    ner_service_port: int = 8765
    ner_batch_size: int = 32
    ner_max_wait_ms: int = 20
    work_base_dir: Path = field(default_factory=lambda: Path("/tmp/repo-san-work"))
    keep_work_dirs: bool = False


@dataclass
class OutputConfig:
    artifacts_dir: Path = field(default_factory=lambda: Path("./batch-artifacts"))
    state_file: Path = field(default_factory=lambda: Path("./batch_state.json"))


@dataclass
class BatchConfig:
    gitlab: GitLabConfig
    scope: ScopeConfig
    processing: ProcessingConfig
    output: OutputConfig
    rulepack: str = "examples/rules"
    salt_env: str = "REPO_SANITIZER_SALT"


def load_batch_config(path: Path) -> BatchConfig:
    """Load batch configuration from a YAML file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    gl_raw = raw.get("gitlab", {})
    gitlab = GitLabConfig(
        url=_normalize_gitlab_url(gl_raw["url"]),
        token_env=gl_raw.get("token_env", "GITLAB_TOKEN"),
        source_group=gl_raw["source_group"],
        delivery_group=gl_raw["delivery_group"],
        clone_depth=int(gl_raw.get("clone_depth", 0)),
    )

    scope_raw = raw.get("scope", {})
    scope = ScopeConfig(
        all=bool(scope_raw.get("all", False)),
        partners=list(scope_raw.get("partners") or []),
        repos=list(scope_raw.get("repos") or []),
    )

    proc_raw = raw.get("processing", {})
    processing = ProcessingConfig(
        workers=int(proc_raw.get("workers", 8)),
        ner_service_port=int(proc_raw.get("ner_service_port", 8765)),
        ner_batch_size=int(proc_raw.get("ner_batch_size", 32)),
        ner_max_wait_ms=int(proc_raw.get("ner_max_wait_ms", 20)),
        work_base_dir=Path(proc_raw.get("work_base_dir", "/tmp/repo-san-work")),
        keep_work_dirs=bool(proc_raw.get("keep_work_dirs", False)),
    )

    out_raw = raw.get("output", {})
    output = OutputConfig(
        artifacts_dir=Path(out_raw.get("artifacts_dir", "./batch-artifacts")),
        state_file=Path(out_raw.get("state_file", "./batch_state.json")),
    )

    return BatchConfig(
        gitlab=gitlab,
        scope=scope,
        processing=processing,
        output=output,
        rulepack=raw.get("rulepack", "examples/rules"),
        salt_env=raw.get("salt_env", "REPO_SANITIZER_SALT"),
    )


def _normalize_gitlab_url(raw_url: str) -> str:
    url = str(raw_url).strip()
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            "gitlab.url must be an absolute URL like https://gitlab.com."
        )
    if parsed.query or parsed.fragment:
        raise ValueError("gitlab.url must not contain query params or fragments.")

    path = parsed.path.rstrip("/")
    path_parts = [part for part in path.split("/") if part]
    if len(path_parts) > 1 and not path.endswith("/api/v4"):
        raise ValueError(
            "gitlab.url must point to the GitLab host (for example, "
            "https://gitlab.com), not a group/project path. Put groups into "
            "source_group/delivery_group."
        )

    if path:
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return f"{parsed.scheme}://{parsed.netloc}"
