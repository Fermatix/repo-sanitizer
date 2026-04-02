# 9. Security Properties and Guarantees

This document provides a formal treatment of the security properties that repo-sanitizer is designed to provide, together with their precise scope, the mechanisms that enforce them, and the known limitations where the guarantees do not hold.

---

## 9.1 Formal Threat Model

### Adversary Model

The primary adversary is the **bundle recipient**: a party who receives the output `sanitized.bundle` and does not possess the salt used during sanitization. The adversary has full access to the bundle, can clone it, inspect all branches and tags, and read all commit metadata and file contents.

The adversary's goal is to recover any sensitive value — a credential, a personal identifier, an internal domain name, or a corporate codename — from the bundle.

### Trust Boundary

```
[Source repository]     [Sanitizing party]     [Bundle recipient]
       │                       │                       │
       │──── clone ────────────▶│                       │
       │                        │── sanitize ──────────▶│
       │                        │                       │
       │                Salt (REPO_SANITIZER_SALT)       │
       │                ← kept by sanitizing party       │
       │                        │            NO SALT     │
```

The salt remains with the sanitizing party. The bundle recipient never receives it.

### Covered Attack Surfaces

| Attack surface | Redaction mechanism | Verification |
|---|---|---|
| Working tree files at `--rev` | `apply_redactions()`, file deletion | Post-scan (Step 5), gates SECRETS/PII_HIGH/DICTIONARY/ENDPOINTS |
| Commit author names | `name_callback` in filter script | History post-scan (Step 8) |
| Commit author emails | `email_callback` in filter script | History post-scan (Step 8) |
| Commit committer names | `name_callback` in filter script | History post-scan (Step 8) |
| Commit committer emails | `email_callback` in filter script | History post-scan (Step 8) |
| Commit message bodies | `message_callback` in filter script | History post-scan (Step 8) |
| Historical file blob contents | `blob_callback` in filter script | History blob post-scan (Step 8b) |
| Deny-glob files in all commits | `filename_callback` in filter script | Gate FORBIDDEN_FILES |

---

## 9.2 Determinism and Reproducibility

### Formal Definition

**Claim:** For a fixed salt `s` and source repository `R`, two independent executions of `run_sanitize(R, s, rulepack)` produce byte-identical output bundles.

This claim holds because determinism is guaranteed at three independent levels:

**Level 1 — Cryptographic function:**

```python
HMAC-SHA256(s, v) is a pure function of s and v.
truncate(HMAC-SHA256(s, v), 12) is also pure.
```

For any value `v`, `_hash(s, v)` produces the same 12-character hex string on every call.

**Level 2 — Replacement ordering:**

```python
sorted(findings, key=lambda f: f.offset_start, reverse=True)
```

`sorted()` is stable and total over a fixed set of integer offsets. Given the same `pre_findings` (which are determined by the detector outputs on fixed file content), the same replacement sequence is applied.

**Level 3 — git-filter-repo:**

Given identical source history and identical callback functions (which are deterministic because they use only `_hash()`), `git-filter-repo` produces git objects with identical SHAs and hence a byte-identical bundle.

### Cross-Repository Consistency

Because the salt is shared across repositories within a batch run, the same email address appearing in two different repositories receives the same replacement:

```
alice@corp.internal  ──salt──→  REDACTED_EMAIL_a1b2c3d4e5f6
```

This enables cross-repository traceability: an auditor can determine that the same entity appears in multiple repositories by comparing anonymized values, without learning the original identity.

### When Determinism Does Not Hold

Determinism is broken by:

1. **Different salt values** across runs — intentional; prevents cross-run correlation.
2. **Different rulepack** — different patterns produce different findings, hence different replacements.
3. **Different source repository state** — a changed file produces different detector outputs.
4. **Non-deterministic detector outputs** — NER models may produce slightly different entity boundaries across library versions; this is a known limitation.

---

## 9.3 Source Value Non-Disclosure

### In-Memory Protection

The `Finding.matched_value` field is declared with `repr=False`:

```python
matched_value: str = field(repr=False)
```

This prevents the sensitive value from appearing in:
- Python's default string representation of the dataclass (`repr(finding)`)
- Log output when the finding is logged via `logging.debug("Finding: %r", finding)`
- Exception tracebacks that print the dataclass's `__repr__`

### On-Disk Protection

Scan report artifacts (`scan_report_pre.json`, `history_scan_pre.json`, etc.) are written using `Finding.to_report()`, which excludes `matched_value`. Only `value_hash` appears in these files.

The one exception is `artifacts/redaction_manifest.json`, which records `original_value` alongside `replacement` for audit purposes. This file:

- Is written to the `artifacts/` directory, not to `output/`.
- Is **never** included in `output/sanitized.bundle`.
- Must be retained securely by the sanitizing party and never shared with the bundle recipient.

### Value Hash One-Wayness

The `value_hash` field in scan reports is:

```python
HMAC-SHA256(salt, matched_value.encode()).hexdigest()[:12]
```

This is a keyed one-way function. A bundle recipient who does not know the salt cannot:

- Determine `matched_value` from `value_hash`.
- Verify whether a known candidate value `v'` has `_hash(s, v') == value_hash` (without the salt).
- Build a rainbow table over candidate values (the key `s` renders precomputed tables useless).

### Salt Transmission Security

The salt is accepted exclusively via an environment variable (`REPO_SANITIZER_SALT`), never as a CLI argument. This prevents the salt from appearing in:

- Shell history files (`~/.bash_history`, `~/.zsh_history`, `~/.history`)
- Process listings visible to other users (`ps aux`, `top`)
- `/proc/*/cmdline` on Linux systems

---

## 9.4 Isolation Properties

### Working Copy Isolation

The pipeline operates exclusively on a copy of the source repository cloned into `work_dir`. The source repository is never modified:

- Local sources are cloned with `git clone --no-hardlinks` (no shared inodes).
- Remote sources are cloned via `git clone` into an isolated directory.
- Plain directories are copied with `shutil.copytree`.

### Git Configuration Isolation

The history rewrite subprocess is executed with all git configuration sources redirected to `/dev/null`:

```python
env["GIT_CONFIG_NOSYSTEM"] = "1"
env["GIT_CONFIG_SYSTEM"]   = os.devnull
env["GIT_CONFIG_GLOBAL"]   = os.devnull
```

This ensures that:
- No user-specific git configuration (credential helpers, proxy settings, alias definitions) affects the rewrite.
- The rewrite is reproducible across different operator environments with different git configurations.

### Process Isolation in Batch Mode

Batch workers are spawned as separate OS processes via `ProcessPoolExecutor`. This means:

- A fatal exception in one worker (segfault, OOM, assertion error) does not terminate other workers.
- State corruption in one worker's address space cannot propagate to others.
- The orchestrator detects worker failures through the return value and updates the state file accordingly.

---

## 9.5 Gate Check Completeness

The six security gates provide machine-readable postconditions of a successful pipeline run.

### Gate Postconditions

| Gate | Postcondition when passed |
|---|---|
| `SECRETS` | `∀ f ∈ (post_findings ∪ history_post_findings ∪ history_blob_post_findings): f.category ≠ SECRET` |
| `PII_HIGH` | `∀ f ∈ all_post: ¬(f.category = PII ∧ f.severity = HIGH)` |
| `DICTIONARY` | `∀ f ∈ all_post: f.category ≠ DICTIONARY` |
| `ENDPOINTS` | `∀ f ∈ all_post: f.category ≠ ENDPOINT` |
| `FORBIDDEN_FILES` | `∀ item ∈ inventory: item.action = DELETE → ¬exists(work_dir / item.path)` |
| `CONFIGS` | `∀ item: fnmatch(item.name, deny_glob) ∧ ¬has_allow_suffix(item) → ¬exists(work_dir / item.path)` |

An `exit_code` of 0 in `result.json` is the machine-readable assertion that all six postconditions hold.

### Scope of Gate Verification

Gates check the output of the post-sanitization scans. Crucially:
- `post_findings` covers the working tree (Steps 5).
- `history_post_findings` covers commit metadata (Step 8).
- `history_blob_post_findings` covers historical blobs (Step 8b).

A gate-passing result therefore provides evidence that the detector ensemble found no remaining sensitive data across all three attack surfaces.

---

## 9.6 Known Limitations and Scope Boundaries

### Unaddressed Attack Surfaces

| Attack surface | Status | Notes |
|---|---|---|
| PII in file path components | Not addressed | Filename callback removes files entirely; path components are not anonymized |
| PR/MR bodies, comments, labels | Not addressed | Stored in hosting platform API, not in git object store |
| Git LFS objects | Partially addressed | LFS pointer files are processed; LFS storage backend is not accessed |
| Repository wikis | Not addressed | Separate git repositories; must be sanitized independently |
| EXIF metadata in kept images | Not addressed | Binary files in allow-list are retained as-is |
| Commit signatures (GPG/SSH) | Invalidated, not sanitized | History rewrite invalidates signatures; signature content is not inspected before invalidation |
| Recursive submodule content | Not addressed | `.gitmodules` pointer files are scanned; submodule repos are not cloned |
| Git notes | Not addressed | `git notes` are not processed by the pipeline |

### Detector Coverage Gaps

**NERDetector accuracy:** Transformer NER models have finite recall. Typical multilingual NER models achieve F1 scores of 85–92% on benchmark datasets. This means approximately 8–15% of person names and organization names may not be detected. Named entities in languages not well-represented in the model's training data may have lower recall.

**SecretsDetector coverage:** `gitleaks` detection is limited to its built-in ruleset. Secret patterns not covered by the installed version of gitleaks will not be detected by `SecretsDetector`. Custom gitleaks rules can be added via gitleaks configuration files, but this is outside the scope of the rulepack system.

**RegexPIIDetector coverage:** Regex patterns have finite coverage. Phone number formats not matching the configured patterns (e.g., regional formats not included in the rulepack) will not be detected. The default rulepack covers common international and Russian formats; organizations should add patterns for other regional formats as needed.

### Performance-Based Coverage Exclusions

The following detectors are excluded from history blob scans (Steps 6b and 8b) for performance reasons:

| Excluded detector | Impact |
|---|---|
| `SecretsDetector` (gitleaks) | API credentials and secrets in historical blobs (not in working tree or commit metadata) may not be detected |
| `NERDetector` | Person names and organization names in historical blob contents may not be detected |

**Practical impact assessment:** In most repositories, files that once contained secrets have been modified before the scan; the working tree scan (Step 3) provides coverage for the current state. Historical blob coverage for secrets is a defense-in-depth measure for cases where: (a) the secret was added in a feature branch that was never merged, or (b) the working tree version was modified after the secret was introduced but the blob still exists in history.

Organizations with strict compliance requirements should consider:
1. Treating the blob scan as best-effort coverage for PII/endpoints/dictionary terms.
2. Running a separate gitleaks scan over all branches for historical secret detection.
3. Adjusting the rulepack to be more aggressive with deny_globs for files that could contain secrets.

### Redaction Completeness vs. Zone Restriction

Zone-based scanning (see [05-extraction.md](05-extraction.md)) restricts detection to comments and string literals in code files. This means:

- A credential stored as a Python variable assignment without quotes (`PASSWORD = SECRET`) would appear as an identifier and not be detected.
- However, this pattern is uncommon — credentials are almost always string-quoted values or environment variable references.
- The gate checks verify that no remaining findings exist in the post-scan; if detection missed a value in the working tree, the gate `SECRETS` or `PII_HIGH` will **not** fail (because the value was never detected). This is a **false negative at the gate level**, not a gate enforcement failure.

---

## 9.7 Operational Security Recommendations

### Salt Generation

Generate a cryptographically random salt using a system CSPRNG:

```bash
openssl rand -hex 32
# Output: 64-character hex string (256 bits of entropy)
```

A 256-bit HMAC key provides security margin far exceeding any foreseeable attack. Do not use human-memorable strings, UUIDs, or truncated hashes as salts.

### Salt Management

- Store the salt in a secrets management system (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
- Rotate the salt between delivery batches if cross-batch correlation must be prevented.
- Retain the salt for the lifetime of any delivery that may need to be reproduced.
- Losing the salt does not expose any data, but prevents reproduction of the sanitized output.

### Rulepack Review

Before each sanitization run:

1. Review `deny_globs` for completeness — add any organization-specific file types not covered.
2. Review `dict/` files for completeness — add new client names, codenames, and internal domains.
3. Verify the rulepack version is pinned in batch configuration.
4. Test the rulepack on a non-sensitive sample repository before production use.

### Treating exit_code as a Delivery Gate

The `result.json` `exit_code` field must be treated as a mandatory check before delivery:

```bash
repo-sanitizer sanitize ... && deliver_bundle output/sanitized.bundle
#          exit code 0 ───────────────────────────────────────────────^
```

A non-zero exit code indicates that one or more gates failed and sensitive data may remain in the bundle. The bundle must not be delivered until the underlying issues are resolved. Issues may require:

- Adjusting the rulepack (more aggressive deny_globs, additional patterns).
- Manually reviewing files flagged by FORBIDDEN_FILES or CONFIGS gates.
- Investigating whether post-scan findings represent false positives that can be accepted.

### Post-Delivery Verification

After delivery, the recipient can verify bundle integrity using the `bundle_sha256` field from `result.json`:

```bash
sha256sum sanitized.bundle
# Compare with result.json "bundle_sha256" value
```

This ensures that the bundle was not modified during transmission.
