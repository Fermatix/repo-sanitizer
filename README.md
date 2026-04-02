# repo-sanitizer

CLI tool for anonymizing Git repositories before sharing with third parties.

Takes a local path or URL as input. Produces a `git bundle` with fully rewritten history — no PII, secrets, or internal infrastructure data in any commit on any branch.

---

## Quick Start

```bash
# 1. Install
pip install repo-sanitizer

# 2. Set salt (required — never passed via CLI)
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"

# 3. Sanitize
repo-sanitizer sanitize ./my-project \
  --rulepack ./rules \
  --out ./sanitized-output

# 4. Check result
cat sanitized-output/artifacts/result.json

# 5. Share the bundle
git clone sanitized-output/output/sanitized.bundle ./verification
```

---

## Features

| What gets detected | How |
|---|---|
| Secrets (API keys, tokens, passwords) | gitleaks |
| Emails, phone numbers, IPv4 addresses, JWTs, URLs | Regex patterns |
| Internal domains and private IPs (RFC 1918) | EndpointDetector |
| Names and organizations | NER transformer model |
| Custom terms (project codenames, client names) | Dictionary (Aho-Corasick) |

| What gets rewritten | Scope |
|---|---|
| Working tree files | Comments and string literals only (tree-sitter zones) |
| Commit metadata | Author name, email, commit message — all branches |
| File content in history | All unique blobs across all branches |
| Denied files | Removed from every commit |

| Output | |
|---|---|
| `sanitized.bundle` | Git bundle, cloneable |
| `result.json` | Gate results, SHA-256 of bundle, timings |
| Scan reports | Pre/post findings for working tree and history |

All replacements are **deterministic**: same salt + value → same output every time.

---

## Installation

### Requirements

| Tool | Version | Purpose |
|---|---|---|
| Python | ≥ 3.11 | Runtime |
| [gitleaks](https://github.com/gitleaks/gitleaks) | any | Secret detection (required) |
| git | ≥ 2.35 | Clone, log, bundle |

### Python package

```bash
# With uv (recommended)
uv add repo-sanitizer

# With pip
pip install repo-sanitizer

# With all tree-sitter grammars (165+ languages)
pip install "repo-sanitizer[grammars]"
```

### gitleaks

```bash
brew install gitleaks        # macOS
sudo apt install gitleaks    # Linux
scoop install gitleaks       # Windows
```

### NER model (optional, downloaded automatically)

On first run, `transformers` downloads `Davlan/bert-base-multilingual-cased-ner-hrl` (~700 MB) to `~/.cache/huggingface/`. See [docs/offline.md](docs/offline.md) for air-gapped setup.

---

## CLI

| Command | Description |
|---|---|
| `sanitize <source>` | Full pipeline: clone → scan → redact → rewrite history → bundle |
| `scan <source>` | Read-only audit — no changes made |
| `install-grammars` | Verify and install tree-sitter grammar packages |
| `batch run` | Process thousands of GitLab repositories in parallel |
| `batch list` | Dry-run: enumerate repositories without processing |
| `ner-service` | Start a shared NER inference service (foreground); multiple `sanitize`/`scan` runs share one GPU process |

### `sanitize` options

| Option | Default | Description |
|---|---|---|
| `--rulepack PATH` | — | Path to rulepack directory (required) |
| `--out PATH` | — | Output directory (required) |
| `--rev REV` | `HEAD` | Git revision for working tree checkout |
| `--salt-env VAR` | `REPO_SANITIZER_SALT` | Name of env variable holding the salt |
| `--max-file-mb N` | `20` | Skip files larger than N MB |
| `--history-since DATE` | — | Limit history scan start date (git format: `2024-01-01`) |
| `--history-until DATE` | — | Limit history scan end date |
| `--ner-device DEVICE` | `cpu` | NER device: `cpu` \| `cuda` \| `cuda:0` \| `auto` |
| `--ner-service-url URL` | — | URL of a running `ner-service`. Skips local model loading; multiple runs share one service |

**Exit codes:** `0` = all gates passed, `1` = one or more gates failed.

### `scan` options

Same options as `sanitize`. Produces `inventory.json`, `scan_report_pre.json`, `history_scan_pre.json`, `history_blob_scan_pre.json`. No files are modified.

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/pipeline.md](docs/pipeline.md) | All 10 pipeline steps, detectors, replacement masks, artifacts |
| [docs/rulepack-authoring.md](docs/rulepack-authoring.md) | Writing policies.yaml, extractors.yaml, regex patterns, dictionaries |
| [docs/batch.md](docs/batch.md) | Processing 2500+ GitLab repositories in parallel |
| [docs/architecture.md](docs/architecture.md) | Internal design: RunContext, data flow, history rewrite, determinism |
| [docs/offline.md](docs/offline.md) | Air-gapped / offline environment setup |

---

## Development

```bash
git clone <repo-url> && cd repo-sanitizer
uv sync --dev

# Fast unit tests (no external tools required)
uv run pytest tests/test_rulepack.py tests/test_redaction.py \
              tests/test_inventory.py tests/test_detectors.py \
              tests/test_extractors.py -v

# All tests (NER and integration tests skip if dependencies missing)
uv run pytest -v

# Run CLI from source
uv run repo-sanitizer --help
```

### Project structure

```
repo_sanitizer/
├── cli.py                    # Entry point (Typer): sanitize, scan, install-grammars, batch
├── context.py                # RunContext: salt, paths, rulepack, findings, timings
├── pipeline.py               # Step orchestrator (run_sanitize / run_scan_only)
├── rulepack.py               # Rulepack loading and validation
├── steps/
│   ├── fetch.py              # Clone / copy
│   ├── inventory.py          # File tree walk and classification
│   ├── scan.py               # Pre-scan and post-scan of working tree
│   ├── redact.py             # Apply replacements
│   ├── history_scan.py       # Scan commit metadata (all branches)
│   ├── history_blob_scan.py  # Scan file content blobs (all branches)
│   ├── history_rewrite.py    # git-filter-repo
│   ├── gate.py               # Gate checks
│   └── package.py            # git bundle create
├── detectors/
│   ├── base.py               # Detector ABC, Finding, ScanTarget, Zone
│   ├── secrets.py            # gitleaks wrapper
│   ├── regex_pii.py          # Email, phone, IP, JWT, URL
│   ├── dictionary.py         # Aho-Corasick over dict files
│   ├── endpoint.py           # Internal domains, private IPs
│   └── ner.py                # Transformer NER: PER, ORG (local + HTTP mode)
├── extractors/
│   ├── treesitter.py         # Tree-sitter extractor
│   └── fallback.py           # Regex fallback for comments
├── redaction/
│   ├── replacements.py       # HMAC masks
│   ├── applier.py            # Span replacement in files
│   └── git_identity.py       # Author normalization
└── batch/                    # Batch mode for thousands of repositories
    ├── config.py
    ├── gitlab_client.py
    ├── ner_service.py
    ├── worker.py
    └── orchestrator.py

examples/
├── rules/                    # Example rulepack
└── batch.yaml                # Example batch config

scripts/
└── run-batch.sh              # Background batch runner (systemd-run / nohup)
```

### Adding a new detector

```python
# repo_sanitizer/detectors/my_detector.py
from repo_sanitizer.detectors.base import Category, Detector, Finding, ScanTarget, Severity

class MyDetector(Detector):
    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []
        # ... detection logic ...
        return findings
```

Register in `steps/scan.py` → `build_detectors()`.

---

## Limitations

The following are out of scope:

- PR/MR data from GitHub/GitLab API
- Wiki repositories
- LFS objects (pointer files are deleted; LFS content is not fetched)
- Recursive submodule processing (`.gitmodules` URLs are caught by EndpointDetector)
- Renaming files or directories whose paths contain PII
- EXIF metadata in images
- Commit signatures (stripped during history rewrite, not analyzed)
