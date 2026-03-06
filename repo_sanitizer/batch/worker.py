"""Worker function executed in a subprocess via ProcessPoolExecutor.

Each worker processes exactly one repository:
  clone → sanitize → push bundle → return result
"""
from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from repo_sanitizer.batch.config import BatchConfig
from repo_sanitizer.batch.gitlab_client import GitLabClient, RepoTask

logger = logging.getLogger(__name__)


@dataclass
class RepoResult:
    partner: str
    name: str
    success: bool
    exit_code: int = -1
    bundle_sha256: str = ""
    error: str = ""

    @property
    def key(self) -> str:
        return f"{self.partner}/{self.name}"


def process_repo(task: RepoTask, config: BatchConfig) -> RepoResult:
    """Sanitize one repository and push its bundle to the delivery GitLab group.

    This function runs inside a worker process spawned by ProcessPoolExecutor.
    It must be importable (no lambda/closures) and all arguments must be picklable.
    """
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [{task.partner}/{task.name}] %(levelname)s %(message)s",
    )

    work_dir = Path(config.processing.work_base_dir) / task.partner / task.name
    out_dir = work_dir / "out"
    artifacts_dir = Path(config.output.artifacts_dir) / task.partner / task.name

    try:
        from repo_sanitizer.pipeline import run_sanitize

        ner_service_url = f"http://127.0.0.1:{config.processing.ner_service_port}"

        exit_code = run_sanitize(
            source=task.clone_url,
            out_dir=out_dir,
            rulepack_path=Path(config.rulepack).resolve(),
            salt_env=config.salt_env,
            ner_service_url=ner_service_url,
        )

        # Copy artifacts to persistent location
        src_artifacts = out_dir / "artifacts"
        if src_artifacts.exists():
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_artifacts, artifacts_dir, dirs_exist_ok=True)

        # Read bundle SHA for state tracking
        bundle_sha256 = _read_bundle_sha(out_dir / "artifacts" / "result.json")

        # Push bundle to delivery GitLab
        bundle_path = out_dir / "output" / "sanitized.bundle"
        token = os.environ.get(config.gitlab.token_env, "")
        client = GitLabClient(
            url=config.gitlab.url,
            token=token,
            source_group=config.gitlab.source_group,
            delivery_group=config.gitlab.delivery_group,
        )
        delivery_url = task.delivery_url or client.ensure_delivery_project(
            task.partner, task.name
        )
        client.push_bundle(bundle_path, delivery_url)

        return RepoResult(
            partner=task.partner,
            name=task.name,
            success=True,
            exit_code=exit_code,
            bundle_sha256=bundle_sha256,
        )

    except Exception as exc:
        logger.exception("Failed to process %s/%s", task.partner, task.name)
        return RepoResult(
            partner=task.partner,
            name=task.name,
            success=False,
            error=str(exc),
        )

    finally:
        if not config.processing.keep_work_dirs and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


def _read_bundle_sha(result_json: Path) -> str:
    if not result_json.exists():
        return ""
    try:
        doc = json.loads(result_json.read_text(encoding="utf-8"))
        return doc.get("bundle_sha256", "")
    except Exception:
        return ""
