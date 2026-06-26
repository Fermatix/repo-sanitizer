"""Local batch runner: sanitize a list of repos from a text file into ./out.

A lighter-weight sibling of the GitLab ``batch`` orchestrator. It reuses the
same per-repo pipeline (``run_sanitize``) and the shared NER service
(``launch_ner_service``), but the source is a local list (paths / bundles /
Git URLs) and the sink is a local output tree — NO GitLab discovery, NO push.

Layout: each repo's output lands in ``<out>/<key>/`` exactly as a single
``sanitize --out <out>/<key>`` would produce it. Progress is tracked in
``<out>/.sanitize_batch_state.json`` so a re-run skips finished repos
(``retry_failed`` re-runs the failed ones); a summary is written to
``<out>/batch_summary.json``.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import multiprocessing
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LocalTask:
    source: str
    key: str
    out_dir: str  # str (not Path) so it is trivially picklable to workers


@dataclass(frozen=True)
class RunParams:
    """Per-run sanitize parameters shared by every worker (picklable)."""
    rulepack_path: str
    salt_env: str
    max_file_mb: int
    ner_device: str | None
    ner_service_url: str | None
    ner_scope: str


@dataclass
class LocalResult:
    key: str
    source: str
    status: str  # "done" (gates green) | "failed" (gates red or error)
    exit_code: int = -1
    error: str = ""


def parse_list_file(path: Path) -> list[str]:
    """Read repo sources from a text file: one per line, ``#`` comments and
    blank lines ignored. Preserves order, drops exact duplicates."""
    if not path.is_file():
        raise FileNotFoundError(f"List file not found: {path}")
    sources: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            sources.append(line)
    if not sources:
        raise ValueError(f"List file {path} contains no repositories.")
    return sources


def _derive_key(source: str) -> str:
    """A filesystem-safe per-repo key for the output subdirectory.

    bundle file -> stem; Git URL -> last path segment minus .git; local
    dir/path -> basename. Callers dedupe collisions.
    """
    s = source.strip()
    if "://" in s or s.startswith("git@"):
        # Git URL (https/ssh). Take the last path segment.
        path_part = urlsplit(s).path if "://" in s else s.split(":", 1)[-1]
        name = path_part.rstrip("/").rsplit("/", 1)[-1]
    else:
        name = Path(s).name
    if name.endswith(".git"):
        name = name[:-4]
    if name.endswith(".bundle"):
        name = name[: -len(".bundle")]
    return name or "repo"


def _build_tasks(sources: list[str], out: Path) -> list[LocalTask]:
    tasks: list[LocalTask] = []
    used: dict[str, int] = {}
    for src in sources:
        base = _derive_key(src)
        n = used.get(base, 0)
        used[base] = n + 1
        key = base if n == 0 else f"{base}-{n + 1}"
        tasks.append(LocalTask(source=src, key=key, out_dir=str(out / key)))
    return tasks


def process_local_repo(task: LocalTask, params: RunParams) -> LocalResult:
    """Worker body (runs in a ProcessPoolExecutor subprocess; must be top-level
    and picklable). Sanitizes one repo into its own out dir — never pushes."""
    logging.basicConfig(
        level=logging.WARNING,
        format=f"%(asctime)s [{task.key}] %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        from repo_sanitizer.pipeline import run_sanitize

        exit_code = run_sanitize(
            source=task.source,
            out_dir=Path(task.out_dir),
            rulepack_path=Path(params.rulepack_path),
            salt_env=params.salt_env,
            max_file_mb=params.max_file_mb,
            ner_device=params.ner_device,
            ner_service_url=params.ner_service_url,
            ner_scope=params.ner_scope,
        )
        return LocalResult(
            key=task.key,
            source=task.source,
            status="done" if exit_code == 0 else "failed",
            exit_code=exit_code,
        )
    except Exception as exc:  # noqa: BLE001 — report, don't crash the pool
        logger.exception("Failed to sanitize %s", task.key)
        return LocalResult(
            key=task.key, source=task.source, status="failed", error=str(exc)
        )


def _load_state(state_file: Path) -> dict:
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state_file: Path, state: dict) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _filter_tasks(tasks: list[LocalTask], state: dict, retry_failed: bool) -> list[LocalTask]:
    """Skip repos already finished; with ``retry_failed`` re-run failed ones."""
    pending: list[LocalTask] = []
    for t in tasks:
        prev = state.get(t.key)
        if prev is None:
            pending.append(t)
        elif prev.get("status") == "failed" and retry_failed:
            pending.append(t)
        # else: status == "done", or "failed" without retry_failed -> skip
    return pending


def run_local_batch(
    *,
    list_file: Path,
    rulepack: Path,
    out: Path,
    workers: int | None = None,
    retry_failed: bool = False,
    salt_env: str = "REPO_SANITIZER_SALT",
    max_file_mb: int = 20,
    ner_device: str | None = None,
    ner_service_url: str | None = None,
    ner_scope: str = "head",
    ner_service_port: int = 8765,
) -> int:
    """Sanitize every repo in ``list_file`` into ``out/<key>``. Returns a
    process exit code: 0 if every processed repo passed its gates, else 1."""
    rulepack = rulepack.resolve()
    out.mkdir(parents=True, exist_ok=True)
    state_file = out / ".sanitize_batch_state.json"

    sources = parse_list_file(list_file)
    tasks = _build_tasks(sources, out)
    state = _load_state(state_file)
    pending = _filter_tasks(tasks, state, retry_failed)

    if workers is None or workers <= 0:
        workers = min(8, max(1, (os.cpu_count() or 2) - 2))
    workers = min(workers, len(pending)) if pending else workers

    skipped = len(tasks) - len(pending)
    logger.info(
        "Local batch: %d repo(s) — %d to process, %d skipped (already done); %d worker(s)",
        len(tasks), len(pending), skipped, workers,
    )
    if not pending:
        logger.info("Nothing to do (all repos already processed; use --retry-failed to redo failures).")
        _write_summary(out, tasks, state)
        return 0 if all(state.get(t.key, {}).get("status") == "done" for t in tasks) else 1

    # Start ONE shared NER service for the whole batch (unless NER is off or the
    # caller pointed us at an external service) — reuses the GitLab-batch machinery.
    ner_proc = None
    effective_ner_url = ner_service_url
    if ner_scope != "off" and not ner_service_url:
        from repo_sanitizer.batch.ner_service import launch_ner_service
        from repo_sanitizer.rulepack import load_rulepack

        rp = load_rulepack(rulepack)
        device = ner_device or rp.ner.device
        logger.info("Starting shared NER service (device=%s, port=%d)...", device, ner_service_port)
        ner_proc = launch_ner_service(
            model_name=rp.ner.model,
            device=device,
            port=ner_service_port,
            batch_size=32,  # GPU forward-pass size; rulepack NER config has no batch_size
            backend=rp.ner.backend,
            min_score=rp.ner.min_score,
            entity_types=rp.ner.entity_types,
        )
        effective_ner_url = f"http://127.0.0.1:{ner_service_port}"

    params = RunParams(
        rulepack_path=str(rulepack),
        salt_env=salt_env,
        max_file_mb=max_file_mb,
        ner_device=ner_device,
        # workers reach NER via the shared service, so they never load the model
        ner_service_url=effective_ner_url,
        ner_scope=ner_scope,
    )

    results: list[LocalResult] = []
    try:
        ctx = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
            fut_to_task = {pool.submit(process_local_repo, t, params): t for t in pending}
            for fut in concurrent.futures.as_completed(fut_to_task):
                t = fut_to_task[fut]
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001
                    res = LocalResult(key=t.key, source=t.source, status="failed", error=str(exc))
                results.append(res)
                state[t.key] = {
                    "source": res.source,
                    "status": res.status,
                    "exit_code": res.exit_code,
                    "error": res.error,
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
                _save_state(state_file, state)
                lvl = logging.INFO if res.status == "done" else logging.ERROR
                logger.log(lvl, "[%s] %s%s", res.key, res.status,
                           f" — {res.error}" if res.error else "")
    finally:
        if ner_proc is not None:
            ner_proc.terminate()
            ner_proc.join(timeout=5)

    _write_summary(out, tasks, state)

    failed = [r for r in results if r.status != "done"]
    done = sum(1 for r in results if r.status == "done")
    logger.info("Local batch done: %d succeeded, %d failed, %d skipped.",
                done, len(failed), skipped)
    return 1 if failed else 0


def _write_summary(out: Path, tasks: list[LocalTask], state: dict) -> None:
    rows = []
    for t in tasks:
        st = state.get(t.key, {})
        rows.append({
            "key": t.key,
            "source": t.source,
            "out_dir": t.out_dir,
            "status": st.get("status", "pending"),
            "exit_code": st.get("exit_code", -1),
            "error": st.get("error", ""),
        })
    doc = {
        "total": len(tasks),
        "done": sum(1 for r in rows if r["status"] == "done"),
        "failed": sum(1 for r in rows if r["status"] == "failed"),
        "pending": sum(1 for r in rows if r["status"] == "pending"),
        "repos": rows,
    }
    (out / "batch_summary.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )
