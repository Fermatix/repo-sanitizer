"""Batch orchestrator.

Coordinates the full batch pipeline:
  1. Start NER service (GPU, shared across all workers)
  2. Enumerate repos from GitLab source group
  3. Filter by scope / state (skip done, optionally retry failed)
  4. Ensure delivery projects exist in GitLab
  5. Run ProcessPoolExecutor with N workers
  6. Track progress in state file (allows resume/retry)
  7. Stop NER service
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from repo_sanitizer.batch.config import BatchConfig, ScopeConfig
from repo_sanitizer.batch.gitlab_client import GitLabClient, RepoTask
from repo_sanitizer.batch.ner_service import launch_ner_service
from repo_sanitizer.batch.worker import RepoResult, process_repo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_batch(
    config: BatchConfig,
    override_partners: Optional[list[str]] = None,
    override_repos: Optional[list[str]] = None,
    retry_failed: bool = False,
) -> int:
    """Run the full batch pipeline. Returns 0 if all repos succeeded, 1 otherwise."""
    token = os.environ.get(config.gitlab.token_env, "")
    if not token:
        raise ValueError(
            f"GitLab token env var '{config.gitlab.token_env}' is not set or empty."
        )

    client = GitLabClient(
        url=config.gitlab.url,
        token=token,
        source_group=config.gitlab.source_group,
        delivery_group=config.gitlab.delivery_group,
    )

    scope = _build_scope(config.scope, override_partners, override_repos)
    all_tasks = client.list_repos(scope)

    state = _load_state(config.output.state_file)
    tasks = _filter_tasks(all_tasks, state, retry_failed)

    if not tasks:
        logger.info("No repositories to process (all done or no matches).")
        return 0

    logger.info(
        "Batch: %d repos to process, %d workers",
        len(tasks),
        config.processing.workers,
    )

    # Pre-create delivery projects so workers don't race on group creation
    logger.info("Ensuring delivery projects exist...")
    for task in tasks:
        task.delivery_url = client.ensure_delivery_project(task.partner, task.name)

    # Load rulepack just to get NER config (model name + device)
    from repo_sanitizer.rulepack import load_rulepack
    rulepack = load_rulepack(Path(config.rulepack).resolve())

    # Start shared NER service
    logger.info("Starting NER service...")
    ner_proc = launch_ner_service(
        model_name=rulepack.ner.model,
        device=rulepack.ner.device,
        port=config.processing.ner_service_port,
        batch_size=config.processing.ner_batch_size,
    )

    failed = 0
    try:
        failed = _run_workers(tasks, config, state)
    finally:
        ner_proc.terminate()
        ner_proc.join(timeout=5)

    _save_state(config.output.state_file, state)
    logger.info("Batch complete. Failed: %d / %d", failed, len(tasks))
    return 0 if failed == 0 else 1


def list_repos(config: BatchConfig) -> list[RepoTask]:
    """Enumerate repos from GitLab without processing them."""
    token = os.environ.get(config.gitlab.token_env, "")
    if not token:
        raise ValueError(
            f"GitLab token env var '{config.gitlab.token_env}' is not set or empty."
        )
    client = GitLabClient(
        url=config.gitlab.url,
        token=token,
        source_group=config.gitlab.source_group,
        delivery_group=config.gitlab.delivery_group,
    )
    return client.list_repos(config.scope)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_workers(
    tasks: list[RepoTask],
    config: BatchConfig,
    state: dict,
) -> int:
    """Submit tasks to ProcessPoolExecutor, update state on completion. Returns fail count."""
    failed = 0

    with concurrent.futures.ProcessPoolExecutor(
        max_workers=config.processing.workers
    ) as pool:
        future_to_task = {
            pool.submit(process_repo, task, config): task for task in tasks
        }

        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            key = f"{task.partner}/{task.name}"
            try:
                result: RepoResult = future.result()
            except Exception as exc:
                result = RepoResult(
                    partner=task.partner,
                    name=task.name,
                    success=False,
                    error=str(exc),
                )

            if result.success:
                state[key] = {
                    "status": "done",
                    "bundle_sha256": result.bundle_sha256,
                    "exit_code": result.exit_code,
                    "ts": _now(),
                }
                logger.info("OK  %s", key)
            else:
                state[key] = {
                    "status": "failed",
                    "error": result.error,
                    "ts": _now(),
                }
                logger.error("FAIL %s — %s", key, result.error)
                failed += 1

            # Persist state after every repo (safe resume on crash)
            _save_state(config.output.state_file, state)

    return failed


def _build_scope(
    base: ScopeConfig,
    override_partners: Optional[list[str]],
    override_repos: Optional[list[str]],
) -> ScopeConfig:
    """Merge config scope with CLI overrides. CLI flags take precedence."""
    if override_repos:
        return ScopeConfig(repos=override_repos)
    if override_partners:
        return ScopeConfig(partners=override_partners)
    return base


def _filter_tasks(
    tasks: list[RepoTask],
    state: dict,
    retry_failed: bool,
) -> list[RepoTask]:
    result = []
    for task in tasks:
        key = f"{task.partner}/{task.name}"
        entry = state.get(key, {})
        status = entry.get("status", "pending")

        if status == "done":
            logger.debug("Skipping (done): %s", key)
            continue
        if status == "failed" and not retry_failed:
            logger.debug("Skipping (failed, use --retry-failed): %s", key)
            continue
        # "running" from a previous crashed run → re-process
        result.append(task)
    return result


def _load_state(state_file: Path) -> dict:
    if state_file.exists():
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_state(state_file: Path, state: dict) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
