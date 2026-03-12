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

from tqdm import tqdm

from repo_sanitizer.batch.config import BatchConfig, ScopeConfig
from repo_sanitizer.batch.gitlab_client import GitLabClient, RepoTask
from repo_sanitizer.batch.ner_service import launch_ner_service
from repo_sanitizer.batch.worker import RepoResult, process_repo
from repo_sanitizer.rulepack import load_rulepack

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _make_gitlab_client(config: BatchConfig, token: str) -> GitLabClient:
    return GitLabClient(
        url=config.gitlab.url,
        token=token,
        source_group=config.gitlab.source_group,
        delivery_group=config.gitlab.delivery_group,
    )


def _get_token(config: BatchConfig) -> str:
    token = os.environ.get(config.gitlab.token_env, "")
    if not token:
        raise ValueError(
            f"GitLab token env var '{config.gitlab.token_env}' is not set or empty."
        )
    return token


def _ensure_delivery_project_isolated(
    partner: str, name: str, config: BatchConfig, token: str
) -> str:
    """Create one delivery project using a fresh GitLabClient (own HTTP session)."""
    return _make_gitlab_client(config, token).ensure_delivery_project(partner, name)


def run_batch(
    config: BatchConfig,
    override_partners: Optional[list[str]] = None,
    override_repos: Optional[list[str]] = None,
    retry_failed: bool = False,
) -> int:
    """Run the full batch pipeline. Returns 0 if all repos succeeded, 1 otherwise."""
    token = _get_token(config)
    client = _make_gitlab_client(config, token)

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

    # Create partner groups sequentially first to avoid race conditions
    # (multiple threads creating the same group → GitLab 500)
    unique_partners = sorted({t.partner for t in tasks})
    logger.info("Ensuring delivery groups for %d partner(s)...", len(unique_partners))
    for partner in unique_partners:
        client.ensure_delivery_partner_group(partner)

    # Create projects in parallel — groups already exist, safe to parallelize.
    # Each thread gets its own GitLabClient (own requests.Session) to avoid
    # ConnectionResetError caused by concurrent use of a shared session.
    logger.info("Ensuring delivery projects exist (%d repos)...", len(tasks))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        fut_to_task = {
            pool.submit(
                _ensure_delivery_project_isolated, t.partner, t.name, config, token
            ): t
            for t in tasks
        }
        for fut in concurrent.futures.as_completed(fut_to_task):
            fut_to_task[fut].delivery_url = fut.result()

    rulepack = load_rulepack(Path(config.rulepack).resolve())

    # Start shared NER service
    logger.info("Starting NER service...")
    ner_proc = launch_ner_service(
        model_name=rulepack.ner.model,
        device=rulepack.ner.device,
        port=config.processing.ner_service_port,
        batch_size=config.processing.ner_batch_size,
        backend=rulepack.ner.backend,
        min_score=rulepack.ner.min_score,
        entity_types=rulepack.ner.entity_types,
    )

    # Create state directory once before the processing loop
    config.output.state_file.parent.mkdir(parents=True, exist_ok=True)

    started_at = _now()
    failed = 0
    results: list[RepoResult] = []
    try:
        failed, results = _run_workers(tasks, config, state)
    finally:
        ner_proc.terminate()
        ner_proc.join(timeout=5)

    _save_state(config.output.state_file, state)
    _save_batch_summary(config, results, started_at)
    logger.info("Batch complete. Failed: %d / %d", failed, len(tasks))
    return 0 if failed == 0 else 1


def list_repos(config: BatchConfig) -> list[RepoTask]:
    """Enumerate repos from GitLab without processing them."""
    client = _make_gitlab_client(config, _get_token(config))
    return client.list_repos(config.scope)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_workers(
    tasks: list[RepoTask],
    config: BatchConfig,
    state: dict,
) -> tuple[int, list[RepoResult]]:
    """Submit tasks to ProcessPoolExecutor, update state on completion.

    Returns (fail_count, all_results).
    """
    failed = 0
    results: list[RepoResult] = []
    total = len(tasks)

    with concurrent.futures.ProcessPoolExecutor(
        max_workers=config.processing.workers
    ) as pool:
        future_to_task = {
            pool.submit(process_repo, task, config): task for task in tasks
        }

        bar = tqdm(
            concurrent.futures.as_completed(future_to_task),
            total=total,
            unit="repo",
            desc="Batch",
            dynamic_ncols=True,
        )
        for future in bar:
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

            results.append(result)
            ts = _now()
            if result.success:
                state[key] = {
                    "status": "done",
                    "bundle_sha256": result.bundle_sha256,
                    "exit_code": result.exit_code,
                    "pushed": result.pushed,
                    "ts": ts,
                }
                bar.write(f"  OK   {key}")
                logger.info("OK   %s", key)
            else:
                state[key] = {"status": "failed", "error": result.error, "ts": ts}
                bar.write(f"  FAIL {key} — {result.error}")
                logger.warning("FAIL %s — %s", key, result.error)
                failed += 1

            bar.set_postfix(ok=len(results) - failed, fail=failed)

            # Persist state after every repo (safe resume on crash)
            _save_state(config.output.state_file, state)

    return failed, results


def _save_batch_summary(
    config: BatchConfig,
    results: list[RepoResult],
    started_at: str,
) -> None:
    """Write batch_summary.json to artifacts_dir with aggregate stats for this run."""
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    pushed = sum(1 for r in results if r.pushed)

    summary = {
        "started_at": started_at,
        "finished_at": _now(),
        "total": total,
        "succeeded": succeeded,
        "failed": total - succeeded,
        "pushed": pushed,
        "repos": [
            {
                "partner": r.partner,
                "name": r.name,
                "status": "done" if r.success else "failed",
                "exit_code": r.exit_code,
                "bundle_sha256": r.bundle_sha256,
                "pushed": r.pushed,
                "error": r.error,
            }
            for r in results
        ],
    }

    summary_path = Path(config.output.artifacts_dir) / "batch_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info("Batch summary → %s", summary_path)


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
    state_file.write_text(
        json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
