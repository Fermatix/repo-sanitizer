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
from datetime import datetime, timezone
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
    pushed: bool = False
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
        level=logging.WARNING,
        format=f"%(asctime)s [{task.partner}/{task.name}] %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    work_dir = Path(config.processing.work_base_dir) / task.partner / task.name
    out_dir = work_dir / "out"
    artifacts_dir = Path(config.output.artifacts_dir) / task.partner / task.name
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    exit_code = -1
    bundle_sha256 = ""
    pushed = False

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
            shutil.copytree(src_artifacts, artifacts_dir, dirs_exist_ok=True)

        # Read bundle SHA for state tracking
        result_json = out_dir / "artifacts" / "result.json"
        bundle_sha256 = _read_bundle_sha(result_json)

        # NEVER deliver a bundle whose REAL-LEAK gates are red. Brand-worklist
        # gates (DICTIONARY/ORG_NAME/BRAND_*/PACKAGE_NAMESPACE) are INTENTIONALLY
        # red after Pass-1 (the Pass-2 rename worklist) and must NOT block the
        # handoff; secrets/PII/endpoints/forbidden-files/configs being red means an
        # actual leak — refuse to push.
        blocking = _blocking_gate_failures(result_json)
        if blocking:
            logger.error(
                "Refusing to push %s/%s — blocking gates failed: %s",
                task.partner, task.name, ", ".join(blocking),
            )
            result = RepoResult(
                partner=task.partner,
                name=task.name,
                success=False,
                exit_code=exit_code,
                bundle_sha256=bundle_sha256,
                pushed=False,
                error=f"blocking gates failed: {', '.join(blocking)}",
            )
        else:
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
            pushed = True

            result = RepoResult(
                partner=task.partner,
                name=task.name,
                success=True,
                exit_code=exit_code,
                bundle_sha256=bundle_sha256,
                pushed=True,
            )

    except Exception as exc:
        from repo_sanitizer.steps.package import EmptyRepositoryError
        if isinstance(exc, EmptyRepositoryError):
            logger.warning("Skipping %s/%s: %s", task.partner, task.name, exc)
            result = RepoResult(
                partner=task.partner,
                name=task.name,
                success=True,
                exit_code=0,
                error="skipped: empty repository",
            )
        else:
            logger.exception("Failed to process %s/%s", task.partner, task.name)
            result = RepoResult(
                partner=task.partner,
                name=task.name,
                success=False,
                exit_code=exit_code,
                bundle_sha256=bundle_sha256,
                pushed=pushed,
                error=str(exc),
            )

    finally:
        _write_batch_result(artifacts_dir, result)
        if not config.processing.keep_work_dirs and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

    return result


def _write_batch_result(artifacts_dir: Path, result: RepoResult) -> None:
    """Write per-repo batch_result.json with sanitize + push outcome."""
    doc = {
        "partner": result.partner,
        "name": result.name,
        "status": "done" if result.success else "failed",
        "exit_code": result.exit_code,
        "bundle_sha256": result.bundle_sha256,
        "pushed": result.pushed,
        "error": result.error,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    (artifacts_dir / "batch_result.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# Gates that represent an ACTUAL leak and must block delivery. The brand gates
# (DICTIONARY/ORG_NAME/BRAND_IDENTIFIER/BRAND_PATH/PACKAGE_NAMESPACE) are
# intentionally red after Pass-1 (the Pass-2 worklist) and are NOT in this set.
#
# BY DESIGN (Option A): the batch delivery group is the INTERNAL Pass-1→Pass-2
# staging area, never the client. Pass-1 output ALWAYS has red brand gates, so
# blocking on them would make batch deliver nothing; the coherent brand→AcmeN
# rename (Pass-2) + apply-map (Pass-3) + the mandatory codex/agent audit run
# AFTER this staging push and are what the client ultimately receives. Do NOT
# point `gitlab.delivery_group` at a client-visible location.
_BLOCKING_GATES = frozenset(
    {"SECRETS", "PII_HIGH", "ENDPOINTS", "FORBIDDEN_FILES", "CONFIGS"}
)


def _blocking_gate_failures(result_json: Path) -> list[str]:
    """Return the names of failed real-leak gates (empty = safe to deliver).

    Fail CLOSED: if result.json is missing/unreadable or has no gates section,
    treat it as a blocking failure rather than silently delivering.
    """
    try:
        doc = json.loads(result_json.read_text(encoding="utf-8"))
    except Exception:
        return ["<no result.json>"]
    gates = doc.get("gates")
    if not isinstance(gates, dict):
        return ["<no gates in result.json>"]
    failed = [
        name for name in _BLOCKING_GATES
        if not gates.get(name, {}).get("passed", False)
    ]
    return sorted(failed)


def _read_bundle_sha(result_json: Path) -> str:
    try:
        doc = json.loads(result_json.read_text(encoding="utf-8"))
        return doc.get("bundle_sha256", "")
    except Exception:
        return ""
