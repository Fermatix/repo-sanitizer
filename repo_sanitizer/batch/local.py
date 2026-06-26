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
import getpass
import json
import logging
import multiprocessing
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)


@dataclass
class LocalTask:
    source: str  # original, as listed — used for key/display/state (never carries a token)
    key: str
    out_dir: str  # str (not Path) so it is trivially picklable to workers
    clone_url: str = ""  # what the worker actually clones (may be an ssh or token URL)

    def __post_init__(self) -> None:
        if not self.clone_url:
            self.clone_url = self.source


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
            source=task.clone_url,
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


# --- pre-flight authorization ---------------------------------------------

# ssh that never blocks on a passphrase/host prompt and auto-trusts new hosts
# (so the later headless worker clones don't trip on an unknown host key).
_SSH_BATCH = "ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new -oConnectTimeout=10"


def _is_http(src: str) -> bool:
    return src.startswith("http://") or src.startswith("https://")


def _is_ssh(src: str) -> bool:
    return src.startswith("git@") or src.startswith("ssh://")


def _ls_remote(url: str, *, ssh: bool = False, prompt: bool = False, timeout: int = 60) -> bool:
    """Return True if `git ls-remote url` authenticates (no hang, no prompt)."""
    env = dict(os.environ)
    if ssh:
        env["GIT_SSH_COMMAND"] = _SSH_BATCH
    if not prompt:
        env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        subprocess.run(
            ["git", "ls-remote", url],
            check=True, capture_output=True, text=True, env=env, timeout=timeout,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _https_to_ssh(url: str) -> str | None:
    """`https://host/group/repo(.git)` -> `git@host:group/repo.git` (scp form)."""
    p = urlsplit(url)
    if not p.hostname or not p.path.strip("/"):
        return None
    path = p.path.lstrip("/")
    if not path.endswith(".git"):
        path += ".git"
    return f"git@{p.hostname}:{path}"


def _inject_creds(url: str, user: str, secret: str) -> str:
    """Put `user:secret@` into an https URL (URL-encoded). Never logged."""
    p = urlsplit(url)
    netloc = f"{quote(user, safe='')}:{quote(secret, safe='')}@{p.hostname}"
    if p.port:
        netloc += f":{p.port}"
    return urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))


def preflight_auth(tasks: list[LocalTask], *, allow_ssh: bool = True) -> list[LocalTask]:
    """Resolve auth for every remote task BEFORE the batch starts.

    Per remote URL, in order: (1) try as-is — existing HTTPS creds (helper /
    token-in-URL); (2) try SSH with the user's keys (rewrites the task to the
    ssh URL on success); (3) if a terminal is attached, prompt once per host
    for a token and bake it into the clone URL. Local paths/bundles need no
    auth. Returns the tasks that still could not authenticate.
    """
    interactive = sys.stdin.isatty() and sys.stderr.isatty()
    remote = [t for t in tasks if _is_http(t.source) or _is_ssh(t.source)]
    if not remote:
        return []
    logger.info("Pre-flight: checking access to %d remote repo(s)...", len(remote))

    need_creds: list[LocalTask] = []  # http(s) that failed as-is and via ssh
    unresolved: list[LocalTask] = []
    for t in remote:
        if _is_ssh(t.source):
            if _ls_remote(t.source, ssh=True):
                continue
            unresolved.append(t)
            continue
        # http(s): 1) as-is (existing creds), 2) ssh fallback
        if _ls_remote(t.source):
            continue
        if allow_ssh:
            ssh_url = _https_to_ssh(t.source)
            if ssh_url and _ls_remote(ssh_url, ssh=True):
                t.clone_url = ssh_url
                logger.info("[%s] authenticated via SSH", t.key)
                continue
        need_creds.append(t)

    # 3) prompt once per host for the still-failing http(s) repos
    if need_creds and interactive:
        creds: dict[str, tuple[str, str]] = {}
        for t in need_creds:
            host = urlsplit(t.source).hostname or ""
            if host not in creds:
                print(f"\nAuthentication required for {host} (e.g. {t.source})", file=sys.stderr)
                user = input(f"  Username for {host} [oauth2]: ").strip() or "oauth2"
                secret = getpass.getpass(f"  Password / access token for {host}: ")
                creds[host] = (user, secret)
            user, secret = creds[host]
            authed = _inject_creds(t.source, user, secret)
            if _ls_remote(authed):
                t.clone_url = authed  # token stays in-memory; logs/state use t.source
                logger.info("[%s] authenticated via HTTPS token", t.key)
            else:
                logger.error("[%s] credentials for %s did not work", t.key, host)
                unresolved.append(t)
    else:
        unresolved.extend(need_creds)

    return unresolved


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
    preflight: bool = True,
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

    # Resolve auth for remote URLs up front (SSH attempt, then credential
    # prompt) so a missing credential aborts BEFORE the NER service + workers
    # spin up — rather than failing each worker headlessly mid-run.
    if preflight and pending:
        unresolved = preflight_auth(pending)
        if unresolved:
            logger.error("Cannot authenticate to %d repo(s) — aborting before start:", len(unresolved))
            for t in unresolved:
                logger.error("  %s", t.source)
            logger.error(
                "Configure credentials (token-in-URL / credential helper / ssh-agent) "
                "or drop these from the list, then re-run. Use --no-preflight to skip this check."
            )
            return 1

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
