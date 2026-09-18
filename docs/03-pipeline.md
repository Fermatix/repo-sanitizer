# 3. Sanitization Pipeline

This document is the authoritative reference for the pipeline steps executed by `repo-sanitizer`. For data structure definitions referenced here, see [02-data-model.md](02-data-model.md). For detector algorithms, see [04-detection.md](04-detection.md). For the redaction scheme, see [06-redaction.md](06-redaction.md).

---

## 3.1 Pipeline Architecture

The pipeline is implemented in `repo_sanitizer/pipeline.py` as a linear sequence of steps sharing a single [`RunContext`](02-data-model.md#26-runcontext) instance. Steps communicate exclusively through the shared context; there are no direct calls between step modules.

Two pipeline variants are provided:

| Function | Steps executed | Purpose |
|---|---|---|
| `run_sanitize()` | All 10 steps | Full sanitization, produces output bundle |
| `run_scan_only()` | Steps 1, 2, 3, 6, 6b | Read-only audit, no modifications |

```
                        ┌─────────────────────────────────────┐
                        │         run_sanitize()              │
                        └─────────────────────────────────────┘
  Step 1      Step 2      Step 3      Step 4      Step 5
┌────────┐  ┌─────────┐  ┌────────┐  ┌────────┐  ┌──────────┐
│ FETCH  │→ │INVENTORY│→ │PRE-SCAN│→ │ REDACT │→ │POST-SCAN │
└────────┘  └─────────┘  └────────┘  └────────┘  └──────────┘
                                                        │
  Step 6      Step 6b     Step 7      Step 8     Step 8b│
┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌──────┴────┐
│HIST META │ │HIST BLOB │ │HIST    │ │HIST    │ │HIST BLOB  │
│SCAN (pre)│→│SCAN (pre)│→│REWRITE │→│META    │→│SCAN (post)│
└──────────┘ └──────────┘ └────────┘ │SCAN    │ └───────────┘
                                      │(post)  │        │
                                      └────────┘        │
                                                        ↓
                                               Step 9      Step 10
                                             ┌────────┐  ┌─────────┐
                                             │  GATE  │→ │PACKAGE  │
                                             │ CHECK  │  │(bundle) │
                                             └────────┘  └─────────┘

─── run_scan_only(): Steps 1, 2, 3, 6, 6b only ───────────────────────
```

---

## 3.2 Step 1 — Fetch

**Implementation:** `repo_sanitizer/steps/fetch.py`

**Input:** Source string (local path, HTTPS URL, or SSH URL) and `--rev` parameter.

**Algorithm:**

1. Detect source type by inspecting the string:
   - Local path with `.git` directory → `git clone --no-hardlinks <source> <work_dir>`
   - HTTP/HTTPS URL or `git@` SSH URL → `git clone <source> <work_dir>`
   - Plain directory without `.git` → `shutil.copytree(<source>, <work_dir>)`
2. For cloned repositories: `git fetch --all` to materialize all remote refs.
3. Check out the specified revision: `git checkout <rev>` (default `HEAD`).

The `--no-hardlinks` flag ensures that local clones do not share inodes with the source repository, preventing accidental modification of the source through hard links.

**Output:** Populated `ctx.work_dir` containing a full copy of the repository.

---

## 3.3 Step 2 — Inventory

**Implementation:** `repo_sanitizer/steps/inventory.py`

**Input:** `ctx.work_dir`, `ctx.rulepack`

**Algorithm:**

1. Walk `work_dir` using `Path.rglob("*")`, skipping `.git/` directory subtrees.
2. For each file, determine `FileCategory`:
   - Check file extension against `CODE_EXTENSIONS` set
   - Check against `DOCS_EXTENSIONS` set
   - Check against CONFIG patterns (files named `.env`, `*.yaml`, `*.toml`, `codeowners`, etc.)
   - Default: `BINARY` (confirmed by MIME type or null-byte probe)
3. For each file, determine `FileAction`:
   - If file extension is in `binary_allow_extensions`: `SKIP`
   - If file extension is in `binary_deny_extensions`: `DELETE`
   - If file size exceeds `max_file_mb * 1024 * 1024`: `SKIP`
   - If filename (with allow-suffix stripped) matches any `deny_glob` pattern:
     - If name has an `allow_suffix`: `SCAN`
     - Otherwise: `DELETE`
   - Default: `SCAN`
4. Construct one `InventoryItem` per file.

**Allow-Suffix Stripping:**

```python
# Example: file = ".env.example", allow_suffixes = [".example"]
base = ".env.example"
for suffix in allow_suffixes:
    if base.endswith(suffix):
        base = base[:-len(suffix)]   # → ".env"
        break
# ".env" matches deny_glob "**/.env" → SCAN (not DELETE)
```

**Artifact:** `artifacts/inventory.json` — array of `InventoryItem.to_dict()` entries.

---

## 3.4 Step 3 — Pre-Scan (Working Tree)

**Implementation:** `repo_sanitizer/steps/scan.py`

**Input:** `ctx.inventory`, `ctx.rulepack`, `ctx.ner_service_url`

**Algorithm:**

1. Instantiate all 5 detectors via `build_detectors(rulepack, ner_service_url)`.
2. For each `InventoryItem` with `action == SCAN`:
   a. Read file content (decode UTF-8 with `errors="replace"`).
   b. Determine zones:
      - If `category == CODE`: call `TreeSitterExtractor.extract_zones(path, content)`
        - If returned `None` (grammar missing): call `FallbackExtractor.extract_zones(path, content)`
        - If returned `[]` (empty): set `zones = []` (no scanning in this file)
      - If `category != CODE`: set `zones = None` (scan entire file)
   c. Construct `ScanTarget(file_path, content, zones)`.
   d. For each detector: call `detector.detect(target)`, collect findings, call `f.compute_hash(ctx.salt)` on each.
3. Log extractor coverage statistics: percentage of CODE files served by tree-sitter vs fallback.
4. Accumulate per-detector timing in `ctx.timings["detectors"]["scan_pre"]`.

**Artifact:** `artifacts/scan_report_pre.json` — array of `Finding.to_report()` entries.

**Stored in:** `ctx.pre_findings`

---

## 3.5 Step 4 — Redact

**Implementation:** `repo_sanitizer/steps/redact.py`

**Input:** `ctx.inventory`, `ctx.pre_findings`, `ctx.salt`

**Algorithm:**

1. Delete all files with `action == DELETE` from `ctx.work_dir`.
2. Group `pre_findings` by `file_path`.
3. For each file with findings:
   a. Read current content.
   b. For CODE files: re-extract zones (consistency check; only findings within a zone are applied).
   c. Call `apply_redactions(content, file_findings, ctx.salt)` — see [§6.2](06-redaction.md#62-working-tree-applier).
   d. Write redacted content back to the file.
   e. Extend `ctx.redaction_manifest` with returned manifest entries.

**Artifact:** `artifacts/redaction_manifest.json` — the only artifact containing `original_value` fields.

---

## 3.6 Step 5 — Post-Scan (Verification)

**Implementation:** `repo_sanitizer/steps/scan.py` (same function, different `report_name` parameter)

Identical to Step 3 but executed on the redacted working tree. Findings are stored in `ctx.post_findings`. Results are written to `artifacts/scan_report_post.json` and consumed by the gate check in Step 9.

A non-empty `post_findings` indicates that redaction was incomplete — either a detector false-negative prevented detection in Step 3, or a finding was outside an extractor zone and was therefore not redacted.

---

## 3.7 Step 6 — History Metadata Scan

**Implementation:** `repo_sanitizer/steps/history_scan.py`

**Input:** `ctx.work_dir`, `ctx.rulepack`, commit time range (`history_since`, `history_until`)

**Algorithm:**

1. Execute `git log --all --format=<custom>` with separators to extract structured fields per commit:
   - `%H` — full SHA
   - `%an` — author name
   - `%ae` — author email
   - `%cn` — committer name
   - `%ce` — committer email
   - `%B` — full commit message body
2. For each commit, create one `ScanTarget` per field (`zones=None`, scan entire value):
   - `file_path = "<commit:{sha8}/{field_name}>"`
3. Run all 5 detectors on each target.
4. Optionally filter by `--history-since` / `--history-until` date strings.

**Artifact:** `artifacts/history_scan_pre.json`

**Stored in:** `ctx.history_pre_findings`

---

## 3.8 Step 6b — History Blob Scan

**Implementation:** `repo_sanitizer/steps/history_blob_scan.py`

**Input:** `ctx.work_dir`, `ctx.rulepack`

### Blob Collection Pipeline

```python
rev_list = Popen(["git", "rev-list", "--objects", "--all"], stdout=PIPE, cwd=work_dir)
cat_file = Popen(
    ["git", "cat-file", "--batch-check=%(objecttype) %(objectname) %(rest)"],
    stdin=rev_list.stdout, stdout=PIPE, cwd=work_dir
)
rev_list.stdout.close()  # allow SIGPIPE propagation
output, _ = cat_file.communicate()
rev_list.wait()
```

This pipeline is O(total_objects) because it processes the object store exactly once via a single `cat-file` invocation connected to `rev-list` via a pipe, rather than spawning one subprocess per commit. Each unique blob SHA is processed exactly once even if it appears in many commits or branches.

### Per-Blob Processing

For each `(blob_sha, path)` pair:

1. Skip if file extension is in `binary_deny_extensions` or `binary_allow_extensions`.
2. Fetch blob content: `git cat-file blob <sha>`.
3. Skip if null bytes found in first 8 KB (binary detection).
4. Skip if byte count exceeds `max_file_mb * 1024 * 1024`.
5. Decode: `raw.decode("utf-8", errors="replace")`.
6. Create `ScanTarget(virtual_path, content, zones=None)` — no zone extraction for blobs.
7. Run the reduced detector set: `RegexPIIDetector`, `DictionaryDetector`, `EndpointDetector`.

**Excluded detectors:**
- `SecretsDetector` — spawning one gitleaks process per blob is prohibitively slow for large histories.
- `NERDetector` — GPU inference per blob has the same cost problem; the shared NER service does not amortize this at the per-blob level.

**Virtual path format:** `<history:{sha8}/{path}>` — preserves the original file path for context while marking the finding as historical.

**Artifact:** `artifacts/history_blob_scan_pre.json`

**Stored in:** `ctx.history_blob_pre_findings`

---

## 3.9 Step 7 — History Rewrite

**Implementation:** `repo_sanitizer/steps/history_rewrite.py`

**Algorithm:**

1. Generate a self-contained Python script (`artifacts/_filter_repo_script.py`) that embeds the rulepack's rules as Python literals. The script has no runtime dependency on `repo_sanitizer`.
2. Execute the script as a subprocess with an isolated git configuration environment:
   ```python
   env["GIT_CONFIG_NOSYSTEM"] = "1"
   env["GIT_CONFIG_SYSTEM"]   = os.devnull
   env["GIT_CONFIG_GLOBAL"]   = os.devnull
   ```
3. The script invokes `git-filter-repo`'s `RepoFilter` with five callbacks (see [§6.4](06-redaction.md#64-history-rewrite)).

**Git config isolation rationale:** `git-filter-repo` internally calls `git config --list` to read configuration. If the user's global `~/.gitconfig` contains shell helper settings with newlines (e.g., `credential.helper = !helper\narg`), the `config --list` output becomes unparseable by filter-repo's Python parser. Setting all config paths to `/dev/null` prevents this crash.

**Filter options:** `force=True, partial=True, replace_refs=update-no-add`

**Artifacts:**
- `artifacts/_filter_repo_script.py` — the generated rewrite script
- `artifacts/history_rewrite_log.txt` — stdout/stderr from git-filter-repo

---

## 3.9b Step 7b — Ref Reconcile

**Implementation:** `repo_sanitizer/steps/ref_reconcile.py`

Runs immediately after the history rewrite (so the post-scans + secret gate certify exactly
the shipped ref set) and again in `apply-map` after the brand rewrite. It makes the output
carry **every** branch with a best-effort scrubbed name, drops all tags, and sets HEAD:

1. Resolve each intake branch's rewritten tip via filter-repo's `commit-map` (authoritative;
   robust to the known `--partial` "stale local head" case), falling back to the in-place
   head, then the intake tip. A branch whose tip pruned to nothing is dropped (logged).
2. Compute a best-effort scrubbed, valid, collision-free ref slug per branch name, reusing
   the same byte-scrubber the rewrite used (`Scrubber.message`) plus a git-ref-name
   sanitizer. Clean names pass through unchanged; a name that resists scrubbing falls back
   to `branch-<hash12>` — a branch is **never** dropped to satisfy name scrubbing.
3. Force-create `refs/heads/<slug>` at each rewritten tip, point HEAD at the scrubbed
   default, then delete every original-named head + all `refs/remotes/*`, `refs/tags/*`,
   `refs/replace/*` (`git update-ref --stdin`, `option no-deref` for symrefs).

Records `ctx.branch_rename_map` / `ctx.output_branches` for the §3.11 gates.

**Priority:** keeping every branch wins over name cleanliness — `CLEAN_REF_NAMES` is advisory.

---

## 3.10 Steps 8 / 8b — History Post-Scans

Exact mirrors of Steps 6 and 6b, executed on the rewritten repository. Results are stored in `ctx.history_post_findings` and `ctx.history_blob_post_findings`.

**Artifacts:** `artifacts/history_scan_post.json`, `artifacts/history_blob_scan_post.json`

---

## 3.11 Step 9 — Gate Checks

**Implementation:** `repo_sanitizer/steps/gate.py`

The gate check combines findings from all three post-sanitization scopes:

```python
all_post = ctx.post_findings + ctx.history_post_findings + ctx.history_blob_post_findings
```

### Gate Definitions

| Gate | Check predicate | Description |
|---|---|---|
| `SECRETS` | `f.category == Category.SECRET` | No secret findings remain |
| `PII_HIGH` | `f.category == Category.PII and f.severity == Severity.HIGH` | No high-severity PII remains |
| `DICTIONARY` | `f.category == Category.DICTIONARY` | No corporate dictionary matches remain |
| `ENDPOINTS` | `f.category == Category.ENDPOINT` | No internal domains/IPs remain |
| `FORBIDDEN_FILES` | File with `action == DELETE` still exists on disk | No forbidden files in output |
| `CONFIGS` | Deny-glob matching file without allow-suffix exists on disk | No bare config files in output |
| `NO_TAGS` | Any `refs/tags/*` remains in the work tree | All tags dropped from the output |
| `BRANCHES_PRESERVED` | An intake branch is neither kept (scrubbed slug) nor pruned-to-nothing | No branch silently lost |
| `CLEAN_REF_NAMES` *(advisory)* | A shipped branch name still matches a brand term / PII pattern | Residual identifier in a branch name — **non-blocking** |

A gate passes if its check produces zero failing items. `all_passed` is `True` only if every **blocking** gate passes (the advisory `CLEAN_REF_NAMES` is excluded — keeping all branches is the priority, so a residual name leak is surfaced for the audit, not a delivery blocker). Exit code 0 indicates a fully sanitized output; exit code 1 must block delivery.

**Artifact:** `artifacts/result.json` — see [§2.8](02-data-model.md#28-json-report-schemas) for the full schema.

---

## 3.12 Step 10 — Package

**Implementation:** `repo_sanitizer/steps/package.py`

**Rule — this step never creates a commit.** The shipped history is the partner's rewritten
history and nothing else: no "Sanitized by repo-sanitizer" tip, no empty commit, no snapshot of
the working tree appended on top of a branch. It is the same rule as for restoration commits —
nothing the pipeline did may appear as a commit on top of the partner history (user decision,
2026-09-18). Packaging reads refs only; it runs no `git add`, `git commit`, `reset` or `clean`.

**Algorithm:**

1. Verify the repository has at least one commit (empty repositories cannot be bundled →
   `EmptyRepositoryError`).
2. Measure the working-tree delta against HEAD — `git status --porcelain=v1 -z -uall` — **without
   changing anything**. Counts go to `artifacts/result.json` (`working_tree_delta`), the paths to
   `artifacts/working_tree_delta.json`; a non-empty delta is logged as a residual (WARNING).
3. Create bundle: `git bundle create output/sanitized.bundle --branches HEAD --` (the trailing `--`
   keeps HEAD a revision when the tree has a top-level `head/` path on a case-insensitive filesystem).
4. Compute SHA-256 of the bundle file.
5. Update `artifacts/result.json` with `bundle_sha256`, `bundle_path` and `working_tree_delta`.

The ref set is owned by the **ref-reconcile step** (§3.9b), which runs after the history
rewrite: it keeps every branch under `refs/heads/*` (with best-effort scrubbed names) and
deletes all tags, remote-tracking refs, and replace refs. Packaging therefore bundles
`--branches HEAD` — every branch plus HEAD — and **never `--all`**, which would re-include
tags and `refs/remotes/*`.

**Why the delta is reported, not committed.** git-filter-repo finishes the history rewrite (§3.9)
with `git reset --hard`, so the working tree already equals the rewritten HEAD; whatever still
differs was never part of the rewritten history — untracked files (`.DS_Store`), NFC/NFD or case
duplicates of a path on APFS/NTFS, a stale leftover of the working-tree redaction pass (§3.5).
Until 2026-09-18 the step committed exactly that delta (`git add -A` + `git commit --allow-empty
-m "Sanitized by repo-sanitizer"`); the nine part-9 tips built this way carried no anonymization
their parent commit lacked and had to be dropped by hand. The bundle is built from refs, so the
working tree cannot leak into it. A redaction that exists **only** in the working tree is a gap in
the history rewrite — add the literal or rule there (`_collect_person_literals`, the secret-literal
plan) — never something to commit.

The resulting bundle is a self-contained git archive. Recipients can clone it directly:

```bash
git clone output/sanitized.bundle my-repo
```

**Output:** `output/sanitized.bundle` (+ `artifacts/working_tree_delta.json`)

---

## 3.13 Timing Instrumentation

Every step records its wall-clock duration in `ctx.timings`:

```python
ctx.timings.setdefault("steps", {})[step_name] = round(elapsed, 3)
ctx.timings.setdefault("detectors", {})[scan_key] = {detector_name: elapsed, ...}
ctx.timings.setdefault("gates", {})[gate_name] = elapsed
```

`total_s` is computed at the end of the pipeline and added to `result.json` by `_patch_result_json()`, which reads the already-written file, merges the total, and rewrites it.

---

## 3.14 Artifact Directory Layout

```
<out_dir>/
├── work/                              # Cloned/copied repository
│   ├── .git/                          # Rewritten git object store
│   └── (redacted source files)
│
├── artifacts/
│   ├── inventory.json                 # Step 2: file catalog
│   ├── scan_report_pre.json           # Step 3: working tree findings (before redaction)
│   ├── redaction_manifest.json        # Step 4: all replacements with original_value
│   ├── scan_report_post.json          # Step 5: working tree findings (after redaction)
│   ├── history_scan_pre.json          # Step 6: commit metadata findings (before rewrite)
│   ├── history_blob_scan_pre.json     # Step 6b: blob findings (before rewrite)
│   ├── _filter_repo_script.py         # Step 7: generated git-filter-repo script
│   ├── history_rewrite_log.txt        # Step 7: git-filter-repo stdout/stderr
│   ├── history_scan_post.json         # Step 8: commit metadata findings (after rewrite)
│   ├── history_blob_scan_post.json    # Step 8b: blob findings (after rewrite)
│   ├── working_tree_delta.json        # Step 10: working tree vs HEAD residual (reported, never committed)
│   └── result.json                    # Step 9/10: gate results, timings, bundle SHA256, working_tree_delta
│
└── output/
    └── sanitized.bundle               # Step 10: deliverable git bundle
```

The `redaction_manifest.json` file is the **only** artifact containing sensitive original values. It must never be included in the output bundle and must be retained securely by the sanitizing party for audit purposes.
