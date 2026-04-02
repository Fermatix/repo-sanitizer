# 8. Batch Processing

This document describes the batch processing mode for sanitizing large numbers of Git repositories in parallel. The batch mode is designed for organizational use cases where hundreds or thousands of repositories from a GitLab instance must be processed and delivered to an external party.

---

## 8.1 Architecture and Design Rationale

### The NER VRAM Problem

`NERDetector` with a HuggingFace or GLiNER backend loads an ML model into memory (or GPU VRAM). A typical multilingual NER model requires approximately 1–1.5 GB of VRAM. If N worker processes each load their own model instance:

- At N=4 workers × 1.2 GB = 4.8 GB VRAM required.
- At N=8 workers × 1.2 GB = 9.6 GB VRAM — exceeds most consumer GPUs.

### Solution: Shared NER HTTP Service

The batch mode starts a single `NERDetector` instance as a FastAPI HTTP server, and all worker processes communicate with it over `localhost`. This means:

- Model is loaded exactly once, regardless of the number of workers.
- VRAM usage is bounded by a single model instance.
- Workers perform all other computation (tree-sitter, regex, gitleaks, git operations) locally using CPU.

### Worker Isolation

Workers are spawned using `ProcessPoolExecutor`. Each worker runs in its own Python process, providing:

- **GIL isolation:** CPU-bound work (tree-sitter parsing, regex matching, Aho-Corasick traversal) scales linearly across cores.
- **Fault isolation:** A crash or exception in one worker does not affect other workers.
- **Memory isolation:** No shared mutable state between workers (except the NER service, which is accessed via HTTP).

### Batch Orchestration Flow

```
┌──────────────────────────────────────────────────────────┐
│                   batch run orchestrator                  │
└──────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
 ┌───────────────┐            ┌─────────────────────┐
 │  GitLab API   │            │   NER HTTP Service   │
 │  list repos   │            │  (started once,      │
 └───────────────┘            │   shared by all      │
         │                    │   workers)           │
         ▼                    └─────────────────────┘
 ┌───────────────┐                     │
 │ state_file    │         ┌───────────┼───────────┐
 │ (pending →   │         │           │           │
 │  running →   │         ▼           ▼           ▼
 │  done/failed)│    ┌────────┐ ┌────────┐ ┌────────┐
 └───────────────┘    │Worker 1│ │Worker 2│ │Worker N│
                      │sanitize│ │sanitize│ │sanitize│
                      └────────┘ └────────┘ └────────┘
                           │          │          │
                           ▼          ▼          ▼
                      ┌────────────────────────────┐
                      │   GitLab delivery group    │
                      │  (push sanitized bundles)  │
                      └────────────────────────────┘
```

---

## 8.2 NER HTTP Service

**Implementation:** `repo_sanitizer/batch/ner_service.py`

### FastAPI Endpoints

**`GET /health`**

Returns service readiness status:

```json
{"status": "ready"}
```

or

```json
{"status": "loading"}
```

The `/health` endpoint returns `"loading"` while the model is being initialized. Workers poll this endpoint before sending inference requests.

**`POST /ner`**

Request body:
```json
{"texts": ["Alice Smith works at...", "Contact bob@example.com"]}
```

Response:
```json
{
  "results": [
    [{"word": "Alice Smith", "entity_group": "PER", "score": 0.98, "start": 0, "end": 11}],
    []
  ]
}
```

The response format matches the HuggingFace `pipeline("ner", aggregation_strategy="simple")` output format, regardless of whether the HF or GLiNER backend is used. This allows `NERDetector` to use a single parsing code path for both local and HTTP inference.

### Dynamic Batching

The service implements request batching at the event loop level to maximize GPU utilization:

```python
async def infer(request: NERRequest) -> NERResponse:
    future = asyncio.get_event_loop().create_future()
    _pending.append((request.texts, future))

    if len(_pending) == 1:
        # First request: yield to collect concurrent requests
        await asyncio.sleep(0)
        # Process all accumulated requests in one batch
        batch_texts = [t for texts, _ in _pending for t in texts]
        results = model(batch_texts)
        # Distribute results back to waiting futures
        offset = 0
        for texts, fut in _pending:
            fut.set_result(results[offset:offset + len(texts)])
            offset += len(texts)
        _pending.clear()

    return await future
```

**How it works:**
1. The first request arrives and is added to `_pending`.
2. `await asyncio.sleep(0)` yields control, allowing other requests from concurrent workers to arrive and be added to `_pending`.
3. All accumulated requests are processed in a single model forward pass.
4. Results are partitioned and returned to each waiting caller.

This approach amortizes the model forward pass overhead across concurrent workers without requiring explicit batching configuration.

### Idle Timeout and Auto-Shutdown

The service monitors time since the last request:

```python
async def idle_watchdog():
    while True:
        await asyncio.sleep(10)
        if time.time() - _last_request_time > idle_timeout:
            os.kill(os.getpid(), signal.SIGTERM)
```

After `idle_timeout` seconds (default 60) with no requests, the service sends itself `SIGTERM` and shuts down. The orchestrator detects the process exit.

### Service Lifecycle

```python
# Orchestrator starts the service:
process = launch_ner_service(port=8765, device="cuda", ...)

# Workers check readiness:
_wait_for_ready(service_url, timeout=120)  # polls /health until "ready"

# Workers use the service:
ctx.ner_service_url = f"http://localhost:8765"

# After all workers complete:
process.terminate()
process.wait()
```

`launch_ner_service()` starts the service as a subprocess and waits for it to become ready (up to 120 seconds, to allow model loading time).

---

## 8.3 batch run Command and batch.yaml Schema

### CLI Command

```bash
repo-sanitizer batch run --config batch.yaml \
  [--partner acme] \
  [--partner contoso] \
  [--repo acme/repo1] \
  [--retry-failed]
```

`--partner` and `--repo` flags override the `scope` section of `batch.yaml` for targeted processing.

### Complete batch.yaml Schema

```yaml
# GitLab connection
gitlab:
  url: https://gitlab.example.com       # Required. GitLab instance URL.
  token_env: GITLAB_TOKEN               # Required. Env var name containing the PAT.
  source_group: partners/acme           # Required. Group path to read repos from.
  delivery_group: secure-delivery/acme  # Required. Group path to push sanitized bundles to.
  clone_depth: 0                        # Optional. 0 = full clone. N > 0 = shallow.

# Processing scope
scope:
  all: false                 # Process all repos in source_group (default false)
  partners:                  # Process all repos under these partner sub-groups
    - acme
    - contoso
  repos:                     # Process specific repos (partner/repo format)
    - acme/legacy-service
    - contoso/api-client

# Worker configuration
processing:
  workers: 8                 # Number of parallel sanitization workers
  ner_service_port: 8765     # Port for the shared NER HTTP service
  ner_batch_size: 32         # Max batch size for NER inference
  work_base_dir: /tmp/repo-san-work  # Base directory for temporary work dirs
  keep_work_dirs: false      # If true, don't delete work dirs after completion

# Output configuration
output:
  artifacts_dir: ./batch-artifacts   # Root dir for all per-repo artifacts
  state_file: ./batch_state.json     # Resumable state tracking

# Rulepack and salt
rulepack: /path/to/rulepack          # Required. Path to rulepack directory.
salt_env: REPO_SANITIZER_SALT        # Required. Env var name for salt.
```

### Field Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `gitlab.url` | string | Yes | Base URL of the GitLab instance (not the group/project) |
| `gitlab.token_env` | string | Yes | Name of env var containing the API token |
| `gitlab.source_group` | string | Yes | GitLab group path to read repositories from |
| `gitlab.delivery_group` | string | Yes | GitLab group path to push sanitized bundles to |
| `gitlab.clone_depth` | int | No | `0` for full clone; `N` for shallow (default `0`) |
| `scope.all` | bool | No | Process all repos in `source_group` |
| `scope.partners` | list | No | Process all repos under these subgroup names |
| `scope.repos` | list | No | Process specific `partner/repo` combinations |
| `processing.workers` | int | No | Parallel workers (default `4`) |
| `processing.ner_service_port` | int | No | NER service port (default `8765`) |
| `processing.ner_batch_size` | int | No | NER batch size (default `32`) |
| `processing.work_base_dir` | string | No | Base dir for temporary work (default `/tmp`) |
| `processing.keep_work_dirs` | bool | No | Retain work dirs after completion (default `false`) |
| `output.artifacts_dir` | string | Yes | Root directory for all per-repo artifacts |
| `output.state_file` | string | Yes | Path to resumable state JSON file |
| `rulepack` | string | Yes | Path to rulepack directory |
| `salt_env` | string | No | Env var name for salt (default `REPO_SANITIZER_SALT`) |

---

## 8.4 State Machine and Resumability

The orchestrator tracks processing state for each repository in `state_file`. This enables resumption after failures without reprocessing already-completed repositories.

### State File Schema

```json
{
  "acme/repo1": {
    "status": "done",
    "started_at": "2024-01-15T10:23:45Z",
    "completed_at": "2024-01-15T10:31:22Z",
    "bundle_sha256": "abc123...",
    "exit_code": 0
  },
  "acme/repo2": {
    "status": "failed",
    "started_at": "2024-01-15T10:24:00Z",
    "completed_at": "2024-01-15T10:25:01Z",
    "error": "gitleaks not found in PATH"
  },
  "contoso/service": {
    "status": "pending"
  }
}
```

### Status Transitions

```
pending ──────→ running ──────→ done
                   │
                   └──────────→ failed
```

On startup, any repository in `running` state is treated as `failed` (crash recovery: the process that was running it no longer exists).

### Resumability

On each run, the orchestrator reads the state file and:

1. Skips repositories with status `done`.
2. Processes repositories with status `pending` or (with `--retry-failed`) `failed`.
3. Updates status to `running` atomically before dispatching a worker.
4. Updates status to `done` or `failed` immediately after the worker completes.

The state file is written after each repository completion (not batched), ensuring that a crash loses at most one repository's work.

### Selective Processing

CLI flags `--partner` and `--repo` take precedence over `scope` configuration:

```bash
# Process only acme repos:
repo-sanitizer batch run --config batch.yaml --partner acme

# Process one specific repo:
repo-sanitizer batch run --config batch.yaml --repo acme/legacy-service

# Retry failed repos:
repo-sanitizer batch run --config batch.yaml --retry-failed
```

---

## 8.5 GitLab Integration

**Implementation:** `repo_sanitizer/batch/gitlab.py`

### API Token Permissions

**Source group token** (read access):
- `read_api` — list repositories in the group
- `read_repository` — clone repositories

**Delivery group token** (write access):
- `api` — create projects in the group
- `write_repository` — push sanitized bundles

Both tokens can be combined in a single token if scope permits.

### ensure_delivery_project()

Before pushing a sanitized bundle, the orchestrator verifies that the destination project exists in the delivery group:

```python
def ensure_delivery_project(gitlab_url, token, delivery_group, project_name):
    # Check if project exists
    response = api_get(f"/groups/{delivery_group}/projects?search={project_name}")
    if not any(p["name"] == project_name for p in response):
        # Create the project
        api_post("/projects", {
            "name": project_name,
            "namespace_id": delivery_group_id,
            "visibility": "private",
        })
```

Each worker maintains its own HTTP session (not shared across workers) to avoid connection pool contention.

---

## 8.6 Artifact Layout for Batch Runs

```
artifacts_dir/
├── batch_summary.json                     # Written at end of batch run
├── acme/
│   ├── repo1/
│   │   ├── inventory.json
│   │   ├── scan_report_pre.json
│   │   ├── scan_report_post.json
│   │   ├── redaction_manifest.json
│   │   ├── history_scan_pre.json
│   │   ├── history_blob_scan_pre.json
│   │   ├── history_rewrite_log.txt
│   │   ├── history_scan_post.json
│   │   ├── history_blob_scan_post.json
│   │   └── result.json
│   └── repo2/
│       └── (same structure)
└── contoso/
    └── service/
        └── (same structure)
```

### batch_summary.json

Written at the end of each batch run:

```json
{
  "run_date": "2024-01-15T12:00:00Z",
  "total_repos": 42,
  "done": 40,
  "failed": 2,
  "failed_repos": ["acme/repo2", "contoso/legacy"],
  "total_redactions": 1842,
  "total_pre_findings": 2103,
  "total_post_findings": 0
}
```

---

## 8.7 Operational Notes

### Salt Security

The salt must be provided via an environment variable, never as a CLI argument. Using a CLI argument would expose the salt in:

- Shell history files (`~/.bash_history`, `~/.zsh_history`)
- Process listings (`ps aux`, `/proc/*/cmdline`)
- System audit logs

**Recommended approach:**

```bash
# Store salt in a .env file (not committed to version control)
echo "REPO_SANITIZER_SALT=$(openssl rand -hex 32)" > .env

# Source before running
source .env
repo-sanitizer batch run --config batch.yaml
```

For automated environments, inject the salt via your secrets manager (Vault, AWS Secrets Manager, etc.) into the process environment.

### Log Access

**Foreground execution:**
```bash
repo-sanitizer batch run --config batch.yaml 2>&1 | tee batch.log
```

**Background with systemd (Linux):**
```bash
systemd-run --user \
  --setenv=REPO_SANITIZER_SALT="$REPO_SANITIZER_SALT" \
  --setenv=GITLAB_TOKEN="$GITLAB_TOKEN" \
  repo-sanitizer batch run --config batch.yaml

# View logs:
journalctl --user -f
```

**Background with nohup (fallback):**
```bash
nohup repo-sanitizer batch run --config batch.yaml > batch.log 2>&1 &
echo $! > batch.pid
```

### Resource Planning

| Resource | Guidance |
|---|---|
| CPU cores | Set `workers` ≈ number of physical cores (git and tree-sitter are CPU-bound) |
| RAM | Each worker requires ~500 MB; NER service requires ~1.5 GB additional |
| GPU VRAM | 1 NER service instance: ~1–1.5 GB VRAM (model-dependent) |
| Disk (work dirs) | Each repo: source size × 3 (clone + artifacts + output); set `keep_work_dirs: false` |
| Network | Each repo: 1 clone + 1 push; parallelize with `workers` limit |
