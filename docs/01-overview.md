# 1. System Overview

## 1.1 Problem Statement

Sharing a Git repository with an external party — a vendor, an auditor, a research collaborator, or an open-source community — exposes substantially more information than the current state of the working tree. A repository is a historical artifact: every file ever committed, every author name and email address, every commit message, and every access credential that was ever accidentally added to any branch, remains permanently encoded in the object store until the history is explicitly rewritten.

Conventional risk-mitigation approaches are insufficient for this threat surface:

- **`.gitignore`** prevents future additions but does not remove existing history.
- **Shallow clones** (`--depth N`) truncate history but are not guaranteed to exclude sensitive objects, and may be deepened by the recipient.
- **Manual review** does not scale to large repositories with long histories across multiple branches.
- **Environment variable substitution** addresses only one category of sensitive data (credentials) and only in the current working tree.

`repo-sanitizer` addresses this gap by providing a fully automated pipeline that:

1. Detects sensitive data across the entire repository — working tree at a specified revision, commit metadata on every branch and tag, and file contents in every unique blob in the object store.
2. Replaces all detected values with deterministic pseudonyms derived from a keyed cryptographic function.
3. Rewrites the full commit graph using `git-filter-repo`, permanently excising both file contents and commit metadata.
4. Validates the sanitized output against a set of security gates before producing a git bundle suitable for delivery.

---

## 1.2 Threat Model

### 1.2.1 Sensitive Data Taxonomy

The system identifies and redacts five categories of sensitive data:

| Category | Description | Examples |
|---|---|---|
| `SECRET` | Cryptographic credentials and API tokens | Private keys, AWS access keys, GitHub PATs, JWT tokens |
| `PII` | Personally Identifiable Information | Email addresses, phone numbers, SSNs, IBAN, passport numbers |
| `ORG_NAME` | Organizational identities | Named entities recognized by NER as organizations |
| `DICTIONARY` | Organization-specific sensitive terms | Client names, internal project codenames, internal product names |
| `ENDPOINT` | Internal infrastructure identifiers | RFC 1918 IP addresses, internal domain names (.internal, .corp) |

### 1.2.2 Attack Surface

The pipeline addresses three distinct attack surfaces within a Git repository:

| Surface | Content | Detection Mechanism |
|---|---|---|
| Working tree | Files at the specified revision (`--rev`, default `HEAD`) | All 5 detectors with AST zone extraction |
| Commit metadata | Author name, author email, committer name, committer email, commit message body for every commit reachable from any branch or tag | All 5 detectors |
| Historical blobs | File contents of every unique blob object reachable from any ref | 3 detectors (RegexPII, Dictionary, Endpoint) |

### 1.2.3 Explicit Scope Exclusions

The following attack surfaces are explicitly **not** addressed by the current implementation:

- **Pull request / merge request bodies and comments** — stored in the hosting platform API, not in the Git object store.
- **Git LFS objects** — large file pointers are rewritten, but LFS storage backends are not accessed.
- **Repository wikis** — separate Git repositories; must be sanitized independently.
- **EXIF metadata in image files** — binary files are either retained as-is (allow-list extensions) or deleted (deny-list extensions); image content is not inspected.
- **File and directory path components** — the filename callback in the history rewrite removes deny-glob files but does not anonymize path components containing PII.
- **Commit signatures** — GPG/SSH signatures are invalidated by history rewriting; the signatures themselves are not sanitized before invalidation.
- **Recursive submodule content** — submodule `.gitmodules` pointer files are scanned, but the referenced submodule repositories are not cloned or sanitized.

---

## 1.3 Security Objectives

The system is designed around four primary security objectives:

**Objective 1 — Completeness.** No sensitive finding produced by the detector ensemble shall remain in any artifact included in the output bundle after a successful pipeline run. This is enforced mechanically by the gate check step (see [Section 3.11](03-pipeline.md#311-step-9--gate-checks)) rather than relying on manual verification.

**Objective 2 — Determinism.** For a fixed salt value `s` and a sensitive value `v`, the replacement `mask(s, v)` is a pure function. The same value always produces the same pseudonym, both within a single repository and across multiple repositories sanitized with the same salt. This property enables traceability without exposing original values.

**Objective 3 — Source Value Non-Disclosure.** Sensitive values detected during scanning are never written to any artifact included in the output bundle. The only artifact that records original values is `artifacts/redaction_manifest.json`, which remains in the sanitizer's local output directory and is not bundled for delivery.

**Objective 4 — Verifiability.** The gate check step produces a machine-readable `artifacts/result.json` containing the pass/fail status of each security gate along with finding counts. An exit code of 0 indicates all gates passed; a non-zero exit code indicates at least one gate failed and the bundle must not be delivered.

---

## 1.4 System Requirements

### 1.4.1 Required Dependencies

| Dependency | Purpose | Minimum Version |
|---|---|---|
| Python | Runtime | ≥ 3.11 |
| git | Repository operations | ≥ 2.35 |
| git-filter-repo | History rewriting | ≥ 2.38 (Python package) |
| gitleaks | Secret detection | Any version with `--no-git` flag |

`gitleaks` must be present in `PATH`. The pipeline raises `RuntimeError` at initialization if `gitleaks` is not found, before any scanning begins.

### 1.4.2 Optional Dependencies

| Dependency | Purpose | Installation |
|---|---|---|
| `transformers` + `torch` | NER backend: HuggingFace | `pip install transformers torch` |
| `gliner` | NER backend: GLiNER (faster, zero-shot) | `pip install gliner` |
| `tree-sitter-language-pack` | 165+ language grammars in one package | `pip install tree-sitter-language-pack` |
| Per-language grammar packages | Individual tree-sitter grammars | `pip install tree-sitter-python` etc. |

If NER dependencies are absent, `NERDetector` raises `ImportError` on first use. If tree-sitter grammars are missing, the system falls back to regex-based comment extraction for the affected languages.

### 1.4.3 Package Management

The project uses `uv` as the package manager:

```bash
uv sync --dev          # install all dependencies including dev
uv run repo-sanitizer  # run the CLI
uv run pytest          # run the test suite
```

---

## 1.5 Document Map

| Document | Contents |
|---|---|
| [02-data-model.md](02-data-model.md) | All core data structures: `Finding`, `Zone`, `ScanTarget`, `RunContext`, `Rulepack` |
| [03-pipeline.md](03-pipeline.md) | The 10-step sanitization pipeline, step-by-step with artifacts |
| [04-detection.md](04-detection.md) | All 5 detector algorithms with complexity analysis |
| [05-extraction.md](05-extraction.md) | Zone extraction: tree-sitter (140+ languages) and fallback |
| [06-redaction.md](06-redaction.md) | Masking scheme, applier algorithm, history rewrite callbacks |
| [07-configuration.md](07-configuration.md) | Rulepack configuration reference — every field, every file |
| [08-batch-processing.md](08-batch-processing.md) | Parallel batch mode, shared NER service, GitLab integration |
| [09-security-properties.md](09-security-properties.md) | Formal security guarantees and known limitations |
