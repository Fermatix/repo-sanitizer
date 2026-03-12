# Architecture

## Overview

The tool is built as a linear pipeline of steps sharing a single state object (`RunContext`). Each step receives the context, does its work, and writes results back to the context and to `artifacts/` on disk.

```
                     ┌──────────────────────────────────────────────────────┐
                     │                     RunContext                        │
                     │  salt · work_dir · rulepack · inventory               │
                     │  pre_findings · post_findings                         │
                     │  history_pre_findings · history_post_findings         │
                     │  history_blob_pre_findings · history_blob_post_findings│
                     │  redaction_manifest · timings                         │
                     └──────────────────────┬───────────────────────────────┘
                                            │  shared state
      ┌─────────────────────────────────────▼──────────────────────────────┐
      │  pipeline.run_sanitize()                                             │
      │                                                                      │
      │   1.  fetch              → work/                                     │
      │   2.  inventory          → inventory.json                            │
      │   3.  scan (pre)         → scan_report_pre.json                     │
      │   4.  redact             → redaction_manifest.json                   │
      │   5.  scan (post)        → scan_report_post.json                    │
      │   6.  history_scan       → history_scan_pre.json    (all branches)  │
      │   6b. history_blob_scan  → history_blob_scan_pre.json (all blobs)   │
      │   7.  history_rewrite    → history_rewrite_log.txt                  │
      │   8.  history_scan       → history_scan_post.json                   │
      │   8b. history_blob_scan  → history_blob_scan_post.json              │
      │   9.  gate_check         → result.json                              │
      │  10.  package            → output/sanitized.bundle                  │
      └──────────────────────────────────────────────────────────────────────┘
```

---

## Key abstractions

### RunContext (`context.py`)

The central state object passed to every step. Created via `RunContext.create()`, which:
- reads the salt from an env variable (required)
- creates `work/`, `artifacts/`, `output/` directories
- accumulates all pipeline state

**Findings fields:**

| Field | Populated in step | Content |
|---|---|---|
| `pre_findings` | 3 | Working tree findings before redaction |
| `post_findings` | 5 | Working tree findings after redaction |
| `history_pre_findings` | 6 | Commit metadata findings (all branches) |
| `history_blob_pre_findings` | 6b | File content findings (all blobs) |
| `history_post_findings` | 8 | Commit metadata findings after rewrite |
| `history_blob_post_findings` | 8b | File content findings after rewrite |

**Timings** accumulate throughout the pipeline and are written to `result.json` at the end:

```
timings
├── total_s                    # total pipeline wall time
├── steps                      # time per step (fetch, scan_pre, redact, …)
├── detectors                  # time per detector per scan
│   ├── scan_report_pre: {SecretsDetector: 5.2, RegexPIIDetector: 3.1, …}
│   └── history_scan_pre: {…}
└── gates                      # time per gate check (SECRETS, PII_HIGH, …)
```

### Detector (`detectors/base.py`)

```python
class Detector(ABC):
    def detect(self, target: ScanTarget) -> list[Finding]: ...
```

Each detector receives a `ScanTarget` (file + content + optional zones) and returns a list of `Finding`. Detectors are stateless with respect to each other and know nothing about the filesystem.

`ScanTarget.zones` is a list of `Zone(start, end)` in byte offsets:
- `zones is None` → scan the entire file
- `zones = []` → scan nothing

`Finding.value_hash` = `HMAC-SHA256(salt, value)[:12]`. Source values are never written to disk.

### TreeSitterExtractor (`extractors/treesitter.py`)

Extracts zones — not a detector. Returns a list of `Zone` (byte offset spans) within which scanning and editing are permitted.

```
extract_zones("app.py", content) → list[Zone] | None

None   — file is not code for this extractor → use fallback
[]     — file is code but has no zones (e.g. only identifiers)
[...]  — list of spans to scan
```

When `on_parse_error: fallback`, returns `None` so the caller can switch to `FallbackExtractor`.

**Grammar resolution order:**

```
_get_parser(lang)
    │
    ├── 1. importlib.import_module(grammar_package)
    │         └── success → tree_sitter.Language(module.language_fn())
    │
    ├── 2. ImportError → _try_language_pack(lang.id)
    │         └── from tree_sitter_language_pack import get_language
    │             get_language(lang.id) → Language object
    │
    └── 3. Both unavailable → RuntimeError (→ FallbackExtractor)
```

Packages with non-standard APIs (e.g. `tree-sitter-typescript`, which exports `language_typescript()` instead of `language()`) are handled via an internal `_GRAMMAR_FN_OVERRIDES` dict. Non-standard IDs for `tree-sitter-language-pack` are handled via `_LANGUAGE_PACK_ID_OVERRIDES`.

`check_grammar_packages(config)` — utility to verify grammar installation without loading parsers. Returns `GrammarStatus` with `via_language_pack=True` when a grammar is found in the pack. Used by `install-grammars` and `_warn_missing_grammars()` in `steps/scan.py`.

---

## Data flow — working tree

```
                 inventory.json
                      │
          ┌───────────▼──────────┐
          │   for each SCAN file │
          └───────────┬──────────┘
                      │
          ┌───────────▼──────────┐          ┌──────────────────────┐
          │  TreeSitterExtractor │─── None──▶│  FallbackExtractor   │
          │  extract_zones()     │           │  (regex comments)    │
          └───────────┬──────────┘           └──────────┬───────────┘
                      │ zones                            │ zones
                      └───────────────┬─────────────────┘
                                      │
                             ┌────────▼────────┐
                             │   ScanTarget     │
                             │  content + zones │
                             └────────┬─────────┘
                                      │
                ┌─────────────────────▼──────────────────────┐
                │            detectors (5)                    │
                │  SecretsDetector                            │
                │  RegexPIIDetector                           │
                │  DictionaryDetector                         │
                │  EndpointDetector                           │
                │  NERDetector                                │
                └─────────────────────┬──────────────────────┘
                                      │ findings
                                      ▼
                           scan_report_pre.json
```

At the end of scanning, `_log_extractor_summary()` prints statistics: how many files were processed via tree-sitter vs. fallback, and which extensions most often fell back.

---

## Data flow — history blobs (steps 6b / 8b)

```
git rev-list --objects --all
         │
         ▼  (pipe)
git cat-file --batch-check=%(objecttype) %(objectname) %(rest)
         │
         ▼
_collect_all_blobs() → list[(sha, path)]   ← deduplicated by SHA
         │
         │  for each unique blob
         ▼
git cat-file blob <sha>
         │
         ├── binary extension? → skip
         ├── binary? (null bytes in first 8KB) → skip
         ├── size > max_file_mb? → skip
         │
         ▼
ScanTarget(
  file_path="<history:abcd1234/path/to/file.py>",
  content=decoded_text,
  zones=None  # entire file scanned
)
         │
         ▼
history_detectors (3):
  RegexPIIDetector
  DictionaryDetector
  EndpointDetector
         │
         ▼
history_blob_scan_pre.json / history_blob_scan_post.json
```

Each unique blob is scanned **once**, even if referenced by many commits. `SecretsDetector` and `NERDetector` are excluded from `build_history_detectors()` — subprocess calls and ML inference per blob are prohibitively slow for large histories.

---

## File redaction

Replacements are applied in `redaction/applier.py`.

**Key invariant:** replacements are applied in **reverse offset order** (end of file first). This ensures that replacing bytes at position N does not shift the offsets of replacements at positions < N.

```python
sorted_findings = sorted(findings, key=lambda f: f.offset_start, reverse=True)
for finding in sorted_findings:
    result = result[:finding.offset_start] + replacement + result[finding.offset_end:]
```

For `code` category files, each finding's span is validated to fall within a tree-sitter zone before the replacement is applied — preventing accidental modification of identifiers.

---

## History rewrite

`steps/history_rewrite.py` generates a temporary self-contained Python script and runs it via `subprocess`. The script uses `git_filter_repo.RepoFilter` with five callbacks:

| Callback | What it does |
|---|---|
| `name_callback` | `author_name → Author_{hash}` |
| `email_callback` | `author_email → author_{hash}@example.invalid` |
| `message_callback` | RegexPII replacements in commit message text |
| `blob_callback` | Email, phone, and all patterns from `pii_patterns.yaml` in text blobs |
| `filename_callback` | Returns `b""` for deny-glob files (removes from all commits) |

Patterns from `pii_patterns.yaml` are serialized into the generated script as a list of `(name, pattern_string)` tuples and compiled as byte-level regex. Each match is replaced with `[name:{hash12}]` using HMAC-SHA256.

The script is generated dynamically so that `git-filter-repo` does not need access to the installed `repo_sanitizer` package — it is self-contained.

---

## Determinism

Determinism is guaranteed at three levels:

1. **Masks** — `HMAC-SHA256(salt, value)[:12]`: identical input → identical output.
2. **Replacement order** — `sorted(findings, key=offset_start, reverse=True)`: stable order.
3. **git-filter-repo** — rewrites history deterministically given identical callbacks.

The salt is stored separately from artifacts. Losing the salt makes it impossible to reproduce the same hashes, but does not expose any data.

---

## Rulepack schema

```
Rulepack
├── version: str                    # from VERSION file
├── deny_globs: list[str]           # fnmatch patterns
├── allow_suffixes: list[str]       # .example / .sample / .template
├── binary_deny_extensions: list
├── binary_allow_extensions: list
├── max_file_mb: int
├── ner: NERConfig
│   ├── backend: str            # "hf" (HuggingFace) | "gliner"
│   ├── model: str              # HF Hub ID or local path
│   ├── min_score: float
│   ├── entity_types: list[str]
│   └── device: str             # cpu | cuda | cuda:0 | cuda:1 | auto  (hf only)
├── extractor: ExtractorConfig
│   ├── languages: list[ExtractorLanguage]
│   │   └── {id, grammar_package, file_extensions, extract_zones}
│   ├── redact_string_literals: bool
│   ├── min_string_length: int
│   ├── on_parse_error: str         # fallback | skip | fail
│   ├── fallback_enabled: bool
│   └── fallback_comment_patterns: list[str]
├── pii_patterns: list[PIIPattern]  # from regex/pii_patterns.yaml
└── dictionaries: dict[str, list[str]]  # from dict/*.txt
```

---

## Error handling

| Situation | Behavior |
|---|---|
| `gitleaks` not found | `RuntimeError` on `SecretsDetector` init → pipeline exit(1) |
| `grammar_package` not installed | Tries `tree-sitter-language-pack`; if also unavailable — WARNING + `FallbackExtractor` |
| `transformers`/model unavailable (`backend: hf`) | `RuntimeError` in `NERDetector._ensure_pipeline()` → pipeline exit(1) |
| `gliner` package not installed (`backend: gliner`) | `RuntimeError` in `NERDetector._ensure_gliner()` → pipeline exit(1) |
| `--ner-service-url` set but service unreachable at startup | `RuntimeError` in `_check_ner_service()` → pipeline exit(1) with message |
| `--ner-service-url` set but service dies mid-run | Retry ×3 with backoff (2 s / 5 s / 10 s), then `RuntimeError` → pipeline exit(1) |
| CUDA requested but unavailable | WARNING + automatic fallback to CPU (`_resolve_device()`); hf only |
| tree-sitter parse error | `on_parse_error: fallback` → `FallbackExtractor`; `skip` → empty zones; `fail` → exception |
| File unreadable | Warning logged, file skipped |
| Salt not set | `ValueError` in `RunContext.create()` with a clear message |
| git-filter-repo exits non-zero | `RuntimeError` with stderr in the message |
| Blob is binary or too large | Skipped silently (counters `skipped_binary`, `skipped_large` logged) |

---

## How to extend the pipeline

### Add a new step

1. Create `steps/my_step.py` with `run_my_step(ctx: RunContext) -> ...`
2. Call it from `pipeline.run_sanitize()` or `run_scan_only()`
3. Write output to `ctx.artifacts_dir / "my_step_output.json"`

### Add a new detector

1. Create `detectors/my_detector.py`, subclassing `Detector`
2. Implement `detect(self, target: ScanTarget) -> list[Finding]`
3. Register in `steps/scan.py` → `build_detectors(rulepack)`
4. Optionally add to `steps/history_blob_scan.py` → `build_history_detectors(rulepack)` if suitable for per-blob scanning
5. Add a replacement mask in `redaction/replacements.py` → `CATEGORY_MASKERS`
6. Write a unit test in `tests/test_detectors.py`

---

## Batch mode internals

### Modules (`repo_sanitizer/batch/`)

| Module | Responsibility |
|---|---|
| `config.py` | `BatchConfig` dataclass + `load_batch_config(path)` |
| `gitlab_client.py` | `GitLabClient`: enumerate repos, ensure delivery projects, push bundles |
| `ner_service.py` | FastAPI NER service: loads model once on GPU, serves inference over HTTP |
| `worker.py` | `process_repo(task, config)` — runs in a subprocess |
| `orchestrator.py` | `run_batch()` / `list_repos()`: NER service → enumerate → workers → state |

### Execution flow

```
repo-sanitizer batch run --config batch.yaml
         │
         ▼
orchestrator.run_batch()
    │
    ├── 1. GitLabClient.list_repos(scope)     ← GitLab API
    │         └── RepoTask[]: partner, name, clone_url, delivery_url
    │
    ├── 2. filter_tasks(state)                ← skip done/failed
    │
    ├── 3. GitLabClient.ensure_delivery_project() × N
    │
    ├── 4. launch_ner_service(model, device, port)
    │         └── FastAPI process, wait for GET /health → "ready"
    │
    ├── 5. ProcessPoolExecutor(workers=N)
    │         └── Worker: process_repo(task)
    │               ├── run_sanitize(clone_url, ner_service_url=http://127.0.0.1:port)
    │               ├── GitLabClient.push_bundle(bundle_path, delivery_url)
    │               └── _write_batch_result(artifacts_dir/<partner>/<name>/batch_result.json)
    │
    ├── 6. ner_proc.terminate()   (or service auto-exits via idle timeout)
    │         └── batch_state.json updated after every repo
    │
    └── 7. _save_batch_summary()
              └── batch_summary.json
```

### NERDetector modes

```
service_url=None, backend="hf"     service_url=None, backend="gliner"    service_url="http://..."
         │                                    │                                    │
         ▼                                    ▼                                    ▼
_ensure_pipeline()                  _ensure_gliner()                   httpx.post("/ner", {"texts": [chunk]})
→ HuggingFace transformers          → GLiNER model                     → NER Service (shared GPU)
  (requires transformers + torch)     (pip install gliner)               retry x3 (2s/5s/10s) on failure
```

`RunContext.ner_service_url` is set when `--ner-service-url` is passed to `sanitize` / `scan`, or internally by the batch orchestrator. It is passed to `build_detectors()` → `NERDetector.__init__`. HTTP mode is available for any backend — both `hf` and `gliner` can run in a service.

When `ner_service_url` is set the pipeline performs a `/health` check before starting; if the service is not reachable or not yet ready the pipeline fails immediately with a clear error message.

### NER HTTP API

```
GET  /health  → {"status": "ready" | "loading"}
POST /ner     → {"texts": ["chunk1", "chunk2"]}
              ← {"results": [[{entity_group, score, word, start, end}, ...], ...]}
```

Response format matches the HuggingFace pipeline with `aggregation_strategy="simple"`.
