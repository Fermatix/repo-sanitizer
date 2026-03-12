# Pipeline reference

## Overview

The `sanitize` command runs a linear 10-step pipeline. Each step writes its output to `artifacts/` and passes state to the next step via `RunContext`.

```
sanitize <source> --rulepack PATH --out PATH

Step 1:  Fetch              → out/work/
Step 2:  Inventory          → artifacts/inventory.json
Step 3:  Pre-scan           → artifacts/scan_report_pre.json
Step 4:  Redact             → artifacts/redaction_manifest.json
Step 5:  Post-scan          → artifacts/scan_report_post.json
Step 6:  History-scan       → artifacts/history_scan_pre.json        (commit metadata, all branches)
Step 6b: History-blob-scan  → artifacts/history_blob_scan_pre.json   (file content, all branches)
Step 7:  History-rewrite    → artifacts/history_rewrite_log.txt
Step 8:  History-post-scan  → artifacts/history_scan_post.json
Step 8b: History-blob-post  → artifacts/history_blob_scan_post.json
Step 9:  Gate check         → artifacts/result.json
Step 10: Package            → output/sanitized.bundle
```

The `scan` command runs steps 1–3 and 6/6b only (read-only, no modifications).

---

## Steps

### Step 1 — Fetch

Clones the repository (or copies a local path) into `out/work/`. The original source is never modified.

### Step 2 — Inventory

Walks the working tree and assigns every file a **category** and an **action**.

**Categories:**

| Category | Examples |
|---|---|
| `code` | `.py`, `.js`, `.ts`, `.go`, `.rs`, … |
| `config` | `.env`, `.yaml`, `.toml`, `.ini` |
| `docs` | `.md`, `.txt`, `.rst`, `.json` |
| `binary` | `.png`, `.exe`, `.zip`, … |

**Actions:**

| Action | Condition |
|---|---|
| `DELETE` | Matches a `deny_glob` and has no allowed suffix |
| `SCAN` | Matches a `deny_glob` but suffix is in `allow_suffixes` (e.g. `.env.template`); or any ordinary text file |
| `SKIP` | Binary with a deny extension (→ DELETE), binary with an allow extension, or exceeds `max_file_mb` |

**Deny-glob matching quirk:** the match is performed against the file's **base name with the allow-suffix stripped**. So `.env.template` → base name `.env` → matches `**/.env` → action `SCAN`.

### Step 3 — Pre-scan

Runs all five detectors on every `SCAN` file in the working tree. For `code` files, scanning is limited to tree-sitter zones (comments + string literals). For `config` and `docs` files, the entire content is scanned.

Results are written to `scan_report_pre.json`.

### Step 4 — Redact

Applies replacements found during pre-scan:

1. Files with action `DELETE` are removed.
2. For `code` files, only the bytes inside tree-sitter zones are modified — identifiers and code structure are untouched.
3. Replacements are applied in **reverse offset order** (end of file first) so that earlier offsets remain valid after each substitution.

All replacements are recorded in `redaction_manifest.json` (hashed values only — originals are never written to disk).

### Step 5 — Post-scan

Re-runs detectors on the redacted working tree. Findings in `scan_report_post.json` feed the gate checks.

### Step 6 — History scan

Scans **commit metadata** across all branches and tags (`git log --all`): author name, author email, committer name, committer email, commit message. Uses the same five detectors.

### Step 6b — History blob scan

Scans **file content** across all unique blobs in the repository history (all branches and tags). Each blob is scanned exactly once, regardless of how many commits reference it.

Detectors used for blobs: `RegexPIIDetector`, `DictionaryDetector`, `EndpointDetector`.

`SecretsDetector` (gitleaks subprocess) and `NERDetector` (ML inference) are excluded — invoking them per-blob is prohibitively slow for large histories.

### Step 7 — History rewrite

Rewrites the entire git history using `git-filter-repo` with five callbacks:

| Callback | What it does |
|---|---|
| `name_callback` | `author_name → Author_{hash}` |
| `email_callback` | `author_email → author_{hash}@example.invalid` |
| `message_callback` | RegexPII replacements in commit message text |
| `blob_callback` | Email, phone, and all patterns from `pii_patterns.yaml` replaced in text blobs |
| `filename_callback` | Files matching `deny_globs` are removed from every commit |

### Steps 8 / 8b — History post-scan

Re-runs history scan and history blob scan on the rewritten history. Results feed the gate checks.

### Step 9 — Gate check

| Gate | Fails when |
|---|---|
| `SECRETS` | Any `category=SECRET` finding in post-scan, history-post-scan, or history-blob-post-scan |
| `PII_HIGH` | Any email, phone, or person finding with `severity=HIGH` in the same sources |
| `FORBIDDEN_FILES` | Any deny-glob file is present in the output tree |
| `CONFIGS` | Any config file without an allowed suffix is present in the output |
| `DICTIONARY` | Any dictionary match remains after redaction |
| `ENDPOINTS` | Any internal domain or private IP remains after redaction |

Exit code `0` = all gates passed. Exit code `1` = one or more gates failed.

### Step 10 — Package

Creates `output/sanitized.bundle` via `git bundle create`. The SHA-256 of the bundle is written to `result.json`.

---

## Detectors

All detectors implement:

```python
class Detector(ABC):
    def detect(self, target: ScanTarget) -> list[Finding]
```

`Finding` fields: `detector`, `category`, `severity`, `file_path`, `line`, `offset_start`, `offset_end`, `value_hash`. Source values are **never written to reports** — only `HMAC-SHA256(salt, value)[:12]`.

### SecretsDetector

Wraps `gitleaks detect --no-git`. Category `SECRET`, severity `CRITICAL`.

> **Required:** if `gitleaks` is not in PATH, the pipeline fails immediately with a clear error.
>
> Not used for history blob scanning (steps 6b/8b) for performance reasons.

### RegexPIIDetector

Patterns loaded from `rulepack/regex/pii_patterns.yaml`. Built-in patterns:

| Pattern | Category | Severity |
|---|---|---|
| Email | `PII` | `HIGH` |
| Phone (E.164) | `PII` | `HIGH` |
| IPv4 | `PII` | `MEDIUM` |
| JWT | `SECRET` | `CRITICAL` |
| HTTPS URL | `ENDPOINT` | `MEDIUM` |

### DictionaryDetector

Aho-Corasick search over `dict/*.txt` files. O(n) in text length, case-insensitive. Lines starting with `#` are comments.

### EndpointDetector

Detects:
- Private IPs (RFC 1918): `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`
- Internal TLDs: `.internal`, `.corp`, `.local`, `.lan`, `.intra`
- Domains listed in `rulepack/dict/domains.txt`

### NERDetector

Named-entity recognition via transformer model `Davlan/bert-base-multilingual-cased-ner-hrl`. Supports Russian and English (F1 ~90%+).

| Model label | Category | Severity |
|---|---|---|
| `PER` | `PII` | `HIGH` |
| `ORG` | `ORG_NAME` | `MEDIUM` |

Entities with score < `ner_min_score` (default `0.7`) or shorter than 3 characters are discarded. Long texts are split into overlapping chunks automatically.

**GPU acceleration:**

```bash
# CLI flag
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device cuda

# Specific GPU
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device cuda:1

# Auto-distribute (requires accelerate)
repo-sanitizer sanitize ./repo --rulepack ./rules --out ./out --ner-device auto
```

If CUDA is requested but `torch.cuda.is_available()` returns `False`, a warning is logged and CPU is used automatically.

**Shared NER service (parallel runs):**

When running multiple `sanitize` or `scan` jobs simultaneously, point them all at a single `ner-service` instead of loading a separate model copy per process:

```bash
# Terminal 1 — start the service once (auto-exits after 60 s of idle)
repo-sanitizer ner-service --port 8765 --device cuda --rulepack ./rules

# Terminal 2 and 3 — jobs share the same GPU process
repo-sanitizer sanitize ./repo-a --rulepack ./rules --out ./out-a --ner-service-url http://localhost:8765
repo-sanitizer sanitize ./repo-b --rulepack ./rules --out ./out-b --ner-service-url http://localhost:8765
```

The pipeline verifies that the service is reachable and ready before starting. If the service becomes unreachable mid-run, the detector retries 3 times (after 2 s, 5 s, 10 s) before aborting with an error.

See [`ner-service` command reference](#ner-service) for all options.

> **Required:** if `transformers` is not installed or the model is unavailable, the pipeline fails with a clear error.
>
> Not used for history blob scanning for performance reasons.

---

## ner-service

Starts a shared NER inference service in the foreground. The model is loaded once; all connected `sanitize` / `scan` runs call it over HTTP.

```
repo-sanitizer ner-service [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--port INT` | `8765` | TCP port to listen on |
| `--device TEXT` | `cpu` | Device: `cpu` \| `cuda` \| `cuda:0` \| `auto` |
| `--backend TEXT` | `hf` | Backend: `hf` (HuggingFace) \| `gliner` |
| `--batch-size INT` | `32` | Max text chunks per GPU forward pass |
| `--model TEXT` | *(from rulepack or default)* | HuggingFace Hub ID or local path |
| `--rulepack PATH` | — | Read `model`, `device`, `backend` defaults from rulepack |
| `--idle-timeout INT` | `60` | Seconds of no requests before auto-shutdown. `0` = never |

**Shutdown:**
- `Ctrl+C` — immediate stop
- Idle timeout — service sends `SIGTERM` to itself after `--idle-timeout` seconds with no incoming requests

**Dynamic batching:** requests from multiple concurrent workers are automatically grouped into a single GPU forward pass. No configuration needed — throughput scales naturally with load.

---

## Replacement masks

All replacements are deterministic: same `salt + value` → same output.

| Type | Output mask |
|---|---|
| Email | `user_{hash12}@example.com` |
| Phone | `+0000000000` |
| Person name (PER) | `Person_{hash12}` |
| Organization (ORG) | `Org_{hash12}` |
| Domain | `{hash8}.example.invalid` |
| IP address | `192.0.2.{1–254}` |
| Author name | `Author_{hash12}` |
| Author email | `author_{hash12}@example.invalid` |
| Secret (gitleaks) | `REDACTED_{hash12}` |
| Regex pattern (pii_patterns.yaml) | `[name:{hash12}]` |

`{hash12}` = `HMAC-SHA256(salt, value).hexdigest()[:12]`

---

## Artifacts

```
out/
├── work/                               # Working copy of repository (modified)
├── output/
│   └── sanitized.bundle                # Final git bundle
└── artifacts/
    ├── inventory.json                  # File list with categories and actions
    ├── scan_report_pre.json            # Working tree findings before redaction
    ├── scan_report_post.json           # Working tree findings after redaction
    ├── redaction_manifest.json         # Applied replacements (hashes only)
    ├── history_scan_pre.json           # Commit metadata findings before rewrite
    ├── history_blob_scan_pre.json      # Blob content findings before rewrite
    ├── history_scan_post.json          # Commit metadata findings after rewrite
    ├── history_blob_scan_post.json     # Blob content findings after rewrite
    ├── history_rewrite_log.txt         # git-filter-repo log
    └── result.json                     # Gate statuses, exit code, bundle SHA-256
```

### result.json

```json
{
  "exit_code": 0,
  "all_passed": true,
  "gates": {
    "SECRETS":          { "passed": true, "failing_count": 0 },
    "PII_HIGH":         { "passed": true, "failing_count": 0 },
    "FORBIDDEN_FILES":  { "passed": true, "failing_count": 0, "files": [] },
    "CONFIGS":          { "passed": true, "failing_count": 0, "files": [] },
    "DICTIONARY":       { "passed": true, "failing_count": 0 },
    "ENDPOINTS":        { "passed": true, "failing_count": 0 }
  },
  "summary": {
    "total_pre_findings": 12,
    "total_post_findings": 0,
    "total_history_pre_findings": 5,
    "total_history_post_findings": 0,
    "total_history_blob_pre_findings": 8,
    "total_history_blob_post_findings": 0,
    "total_redactions": 17
  },
  "timings": {
    "total_s": 142.3,
    "steps": {
      "fetch": 3.2,
      "inventory": 0.1,
      "scan_pre": 12.4,
      "redact": 2.1,
      "scan_post": 11.8,
      "history_scan_pre": 5.3,
      "history_blob_scan_pre": 45.2,
      "history_rewrite": 38.9,
      "history_scan_post": 4.8,
      "history_blob_scan_post": 42.1,
      "gate_check": 0.02,
      "package": 1.8
    },
    "detectors": {
      "scan_report_pre": {
        "SecretsDetector": 5.2,
        "RegexPIIDetector": 3.1,
        "DictionaryDetector": 0.8,
        "EndpointDetector": 0.4,
        "NERDetector": 2.9
      }
    }
  }
}
```

### Finding schema (in scan_report_*.json)

```json
{
  "detector": "RegexPIIDetector",
  "category": "PII",
  "severity": "HIGH",
  "file_path": "src/app.py",
  "line": 4,
  "offset_start": 72,
  "offset_end": 93,
  "value_hash": "3a9f1c2b4e7d"
}
```

`value_hash` = `HMAC-SHA256(salt, original_value)[:12]`. The original value is **never written to disk**.

---

## Language support (tree-sitter)

Tree-sitter is used to extract zones (comments + string literals) from code files. Only bytes inside these zones are scanned and modified.

### Option 1: one package, 165+ languages (recommended)

```bash
pip install tree-sitter-language-pack
# or
pip install "repo-sanitizer[grammars]"
```

Languages listed in `extractors.yaml` that don't have a standalone package are loaded automatically from `tree-sitter-language-pack`.

### Option 2: standalone package per language

```bash
uv add tree-sitter-ruby
```

Add to `extractors.yaml`:

```yaml
- id: ruby
  grammar_package: tree-sitter-ruby
  file_extensions: [.rb]
  extract_zones: [comment_line, comment_block, string_literal]
```

Verify:

```bash
repo-sanitizer install-grammars --rulepack ./my-rules
```

### Grammar resolution order

1. Standalone package (`tree-sitter-ruby`, etc.) — if installed
2. `tree-sitter-language-pack` — if standalone not available
3. `FallbackExtractor` (regex-based comments) — if neither source is available

> **Note for packages with non-standard API** (e.g. `tree-sitter-typescript`): the package exports `language_typescript()` and `language_tsx()` instead of `language()`. Use `id: typescript` and `id: tsx` in `extractors.yaml` — this is handled automatically.
