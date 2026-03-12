# Batch mode

Process thousands of GitLab repositories automatically: clone each one, sanitize it, and push the resulting bundle to a delivery group.

---

## Architecture

The key challenge when running many workers in parallel is the NER model: it occupies ~1.1 GB of VRAM. Loading a separate copy in each of 16 workers would exhaust GPU memory.

**Solution: NER as a dedicated HTTP service.**

```
Orchestrator
├── NER Service (FastAPI, GPU)    ← model loaded once
│     POST /ner → entities
│
├── Worker-0 (process)  ──┐
├── Worker-1 (process)  ──┤── HTTP → NER Service
│   ...                   │
└── Worker-N (process)  ──┘
    Each: clone → sanitize → upload
```

- The NER Service is started by the orchestrator before any workers. It reads `model` and `device` from `policies.yaml`.
- Workers use `ProcessPoolExecutor` — CPU-bound work (tree-sitter, regex, git) scales linearly across all cores.
- `NERDetector` in workers automatically switches to HTTP mode when `ner_service_url` is set.
- To run multiple single-repo jobs in parallel without the batch orchestrator, start the service manually with `repo-sanitizer ner-service` and pass `--ner-service-url` to each `sanitize` / `scan` call. See the [pipeline reference](pipeline.md#ner-service) for details.

---

## Quick start

```bash
# 1. Set environment variables
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"

# 2. Preview which repositories will be processed
repo-sanitizer batch list --config examples/batch.yaml

# 3. Process all repositories
repo-sanitizer batch run --config examples/batch.yaml

# 4. Process only one partner
repo-sanitizer batch run --config examples/batch.yaml --partner acme-corp

# 5. Process only one repository
repo-sanitizer batch run --config examples/batch.yaml --repo acme-corp/backend-api

# 6. Retry only failed repositories from a previous run
repo-sanitizer batch run --config examples/batch.yaml --retry-failed
```

---

## Commands

### `batch run`

```
repo-sanitizer batch run --config PATH [OPTIONS]
```

| Option | Description |
|---|---|
| `--config PATH` | Path to batch YAML config file (required) |
| `--partner NAME` | Process only this partner (repeatable) |
| `--repo PARTNER/NAME` | Process only this repository (repeatable) |
| `--retry-failed` | Retry repositories with status `failed` from a previous run |

CLI flags override the `scope` in the config file. Priority: `--repo` > `--partner` > config `scope`.

### `batch list`

```
repo-sanitizer batch list --config PATH
```

Enumerates repositories from GitLab according to `scope`, without processing anything.

---

## batch.yaml reference

```yaml
# GitLab connection
gitlab:
  url: https://gitlab.example.com
  token_env: GITLAB_TOKEN           # env variable holding the API token
  source_group: partner-private-repos
  delivery_group: partner-private-repos-delivery
  clone_depth: 0                    # 0 = full history

# Processing scope (mutually exclusive; priority: repos > partners > all)
scope:
  all: true
  # partners:
  #   - acme-corp
  # repos:
  #   - acme-corp/backend-api

# Path to rulepack (same as --rulepack)
rulepack: examples/rules

# Env variable holding the salt
salt_env: REPO_SANITIZER_SALT

# Parallelization
processing:
  workers: 16                       # parallel workers
  ner_service_port: 8765            # port for the NER HTTP service
  ner_batch_size: 32                # GPU inference batch size
  work_base_dir: /tmp/repo-san-work # temporary working directories
  keep_work_dirs: false             # delete after push

# Output
output:
  artifacts_dir: ./batch-artifacts  # <dir>/<partner>/<repo>/
  state_file: ./batch_state.json    # progress file (resume / retry)
```

Full example: [`examples/batch.yaml`](../examples/batch.yaml).

### Recommended settings for Threadripper + RTX 2080 Ti

```yaml
processing:
  workers: 16          # ≤ number of physical cores
  ner_batch_size: 32   # tune to available VRAM
  ner_service_port: 8765
```

GPU is kept busy by the NER service; CPU cores handle parallel git/regex/tree-sitter. I/O (clone/push) overlaps with the CPU work of neighboring workers.

---

## GitLab token permissions

| Group | Required permissions |
|---|---|
| `source_group` | `read_api`, `read_repository` |
| `delivery_group` | `api`, `write_repository` |

---

## Progress tracking and resume

Progress is saved to `batch_state.json` after every repository:

```json
{
  "acme-corp/backend-api": {
    "status": "done",
    "bundle_sha256": "abc...",
    "exit_code": 0,
    "pushed": true,
    "ts": "2026-03-09T12:34:56+00:00"
  },
  "acme-corp/frontend": {
    "status": "failed",
    "error": "gitleaks not found",
    "ts": "2026-03-09T12:35:00+00:00"
  }
}
```

| Status | Behavior on next run |
|---|---|
| `done` | Skipped |
| `failed` | Skipped unless `--retry-failed` is passed |
| `running` (from a crashed run) | Treated as `failed`, restarted |

---

## Background execution on Linux

When working over SSH or VS Code Remote, a normal CLI run is tied to the terminal session. Use `scripts/run-batch.sh` for long-running jobs.

**Setup:**

```bash
# Store the salt in .env (already in .gitignore)
echo "REPO_SANITIZER_SALT=your-secret-salt" > .env

chmod +x scripts/run-batch.sh
```

**Managing the job:**

```bash
# Start in background (safe to close the terminal)
./scripts/run-batch.sh start examples/batch.yaml

# Check status from a new terminal
./scripts/run-batch.sh status

# Follow logs in real time
./scripts/run-batch.sh logs

# Stop early
./scripts/run-batch.sh stop
```

The script selects the isolation method automatically:

| Method | Condition | Log access |
|---|---|---|
| `systemd-run --user` | systemd available | `journalctl --user -u repo-sanitizer-batch` |
| `nohup + disown` | systemd not available | `batch.log` in project root |

> **Security:** the salt is passed via environment variable or `.env` file, never as a CLI argument. It does not appear in `ps aux` or `/proc`.

---

## Artifacts

After a run, `artifacts_dir` contains:

```
batch-artifacts/
├── batch_summary.json          # summary for the entire run
├── acme-corp/
│   └── backend-api/
│       ├── batch_result.json   # result for this repository
│       ├── result.json         # gates, bundle SHA, timings
│       ├── inventory.json
│       ├── scan_report_pre.json
│       └── ...
└── big-co/
    └── service/
        ├── batch_result.json
        └── ...
```

### batch_result.json

Written for every repository, including failures:

```json
{
  "partner": "acme-corp",
  "name": "backend-api",
  "status": "done",
  "exit_code": 0,
  "bundle_sha256": "abc123...",
  "pushed": true,
  "error": "",
  "ts": "2026-03-09T12:34:56+00:00"
}
```

### batch_summary.json

Written at the end of each run (overwritten each time):

```json
{
  "started_at": "2026-03-09T10:00:00+00:00",
  "finished_at": "2026-03-09T12:34:56+00:00",
  "total": 42,
  "succeeded": 40,
  "failed": 2,
  "pushed": 40,
  "repos": [
    {
      "partner": "acme-corp",
      "name": "backend-api",
      "status": "done",
      "exit_code": 0,
      "pushed": true,
      "bundle_sha256": "abc...",
      "error": ""
    },
    {
      "partner": "acme-corp",
      "name": "frontend",
      "status": "failed",
      "exit_code": -1,
      "pushed": false,
      "bundle_sha256": "",
      "error": "gitleaks not found"
    }
  ]
}
```
