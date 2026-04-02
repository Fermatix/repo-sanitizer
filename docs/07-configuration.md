# 7. Rulepack Configuration Reference

A *rulepack* is a directory containing the configuration files and data files that govern all aspects of a sanitization pipeline run: which files are deleted, which patterns are detected, which languages use zone extraction, and how the NER model is configured.

This document is the normative specification for rulepack authoring. For operational how-to guidance, see [docs/rulepack-authoring.md](rulepack-authoring.md).

---

## 7.1 Rulepack Structure

```
rulepack/
├── VERSION                        Required. Version string.
├── policies.yaml                  Required. File handling, NER config, size limits.
├── extractors.yaml                Required. Tree-sitter language definitions.
├── regex/
│   └── pii_patterns.yaml          Optional. Regex patterns for RegexPIIDetector.
└── dict/
    ├── clients.txt                Optional. One term per line.
    ├── codenames.txt              Optional. One term per line.
    ├── orgs.txt                   Optional. One term per line.
    └── domains.txt                Optional. Internal domains for EndpointDetector.
```

### VERSION File

Contains a single version string (e.g., `1.2.0`). This value is:
- Logged at pipeline startup.
- Recorded in `artifacts/result.json` for traceability.
- Used to correlate findings with the rulepack version that produced them.

### Configuration Priority Order

When the same setting can be specified in multiple places, the following priority applies (higher overrides lower):

| Priority | Source | Example |
|---|---|---|
| 1 (highest) | CLI flag | `--max-file-mb 50` |
| 2 | Environment variable | `REPO_SANITIZER_SALT=...` |
| 3 | `policies.yaml` value | `max_file_mb: 20` |
| 4 (lowest) | Code default | `max_file_mb = 20` in `RunContext` |

---

## 7.2 policies.yaml Schema

### deny_globs

```yaml
deny_globs:
  - "**/.env"
  - "**/*.key"
  - "**/secrets.*"
```

A list of `fnmatch`-style glob patterns. Files whose names match any pattern are assigned `FileAction.DELETE` — unless they have an `allow_suffix` (see below).

**Pattern matching algorithm:**

```python
from fnmatch import fnmatch

for glob_pat in deny_globs:
    # Use only the filename component of the glob for matching
    pat = glob_pat.split("/")[-1]
    if fnmatch(file.name, pat):
        action = DELETE
        break
```

The default rulepack includes 81 deny_globs covering:

| Category | Examples |
|---|---|
| Environment files | `.env`, `.env.*` |
| Generic config | `config.*`, `settings.*`, `application.*`, `appsettings.*` |
| Cryptographic material | `*.key`, `*.pem`, `*.crt`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |
| SSH keys | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `id_rsa.pub` |
| Cloud credentials | `.boto`, `*.token`, `service-account.json`, `*gcp*.json`, `credentials.json` |
| Auth configuration | `.npmrc`, `.pypirc`, `.netrc`, `.gitcredentials`, `.htpasswd` |
| Kubernetes | `kubeconfig`, `kube.config` |
| Terraform | `*.tfvars`, `terraform.tfstate`, `terraform.tfstate.backup` |
| Ansible | `vault.yml`, `vault.yaml` |
| Certificate stores | `truststore.*`, `cacerts` |

### allow_suffixes

```yaml
allow_suffixes:
  - ".example"
  - ".sample"
  - ".template"
  - ".dist"
  - ".defaults"
```

Files whose full name ends with an allow_suffix receive `FileAction.SCAN` instead of `FileAction.DELETE`, even if their base name (with the suffix stripped) matches a deny_glob.

**Edge case — nested suffixes:**

```
.env.example.template
  → strip ".template" → ".env.example"
  → matches deny_glob? No (not ".env")
  → SCAN
```

Only one suffix is stripped per file. The check is performed against the base name after stripping, not the original name.

### binary_deny_extensions

```yaml
binary_deny_extensions:
  - exe
  - dll
  - so
```

File extensions (without dot) that cause the file to receive `FileAction.DELETE`. Also used in history blob scan to skip binary extension blobs.

The default rulepack includes 48 extensions:

| Category | Extensions |
|---|---|
| Windows executables | `exe`, `dll`, `msi`, `msm`, `msp` |
| Unix executables | `so`, `dylib`, `elf`, `bin` |
| Java bytecode | `class`, `jar`, `war`, `ear` |
| Python bytecode | `pyc`, `pyo`, `pyd` |
| Archives | `zip`, `gz`, `bz2`, `tar`, `rar`, `7z`, `xz`, `lz`, `lzma`, `tgz`, `tbz2` |
| OS packages | `deb`, `rpm`, `pkg`, `dmg`, `apk` |
| Databases | `db`, `sqlite`, `sqlite3`, `mdb`, `accdb` |
| Office documents | `pdf`, `doc`, `docx`, `xls`, `xlsx`, `ppt`, `pptx`, `odt`, `ods`, `odp` |
| Object/lib files | `o`, `a`, `lib` |
| Design files | `psd`, `ai`, `sketch`, `fig`, `xd` |
| Lock files | `lockb` |

### binary_allow_extensions

```yaml
binary_allow_extensions:
  - png
  - jpg
  - svg
```

File extensions for binary files that should be **kept** in the output but not scanned. Assigned `FileAction.SKIP`.

The default rulepack includes 15 extensions: `png`, `jpg`, `jpeg`, `gif`, `bmp`, `ico`, `webp`, `svg`, `ttf`, `otf`, `woff`, `woff2`, `eot`, `cur`, `ani`.

### max_file_mb

```yaml
max_file_mb: 20
```

Maximum file size in megabytes. Files exceeding this limit receive `FileAction.SKIP` and are excluded from scanning. Also applied to history blobs: blobs larger than this threshold are skipped during blob scanning. Default: 20.

### ner block

```yaml
ner:
  backend: gliner          # "hf" | "gliner"
  model: Babelscape/wikineural-multilingual-ner
  min_score: 0.5           # float 0.0–1.0
  entity_types:
    - PER
    - ORG
  device: auto             # "cpu" | "cuda" | "cuda:0" | "auto"
```

| Field | Type | Description | Default |
|---|---|---|---|
| `backend` | `"hf"` or `"gliner"` | Inference backend | `"hf"` |
| `model` | string | HuggingFace model ID | `Davlan/bert-base-multilingual-cased-ner-hrl` |
| `min_score` | float | Minimum entity confidence score | `0.5` |
| `entity_types` | list of strings | Entity labels to detect | `["PER", "ORG"]` |
| `device` | string | Compute device | `"cpu"` |

**Device values:**
- `"cpu"` — CPU inference (always available)
- `"cuda"` — default CUDA device
- `"cuda:0"`, `"cuda:1"`, ... — specific GPU index
- `"auto"` — automatically selects CUDA if available, otherwise CPU

---

## 7.3 extractors.yaml Schema

### treesitter.languages

Each entry defines how to extract zones from files of a given language:

```yaml
treesitter:
  languages:
    - id: python
      grammar_package: tree-sitter-python
      file_extensions:
        - .py
        - .pyw
      extract_zones:
        - comment_line
        - docstring
        - string_literal
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Language identifier (must match `NODE_TYPE_MAP` in `treesitter.py`) |
| `grammar_package` | string | Yes | Python package providing the tree-sitter grammar |
| `file_extensions` | list of strings | Yes | File extensions (with dot) that map to this language |
| `extract_zones` | list of strings | Yes | Zone types to extract (see below) |

**Valid `extract_zones` values:**

| Value | Description |
|---|---|
| `comment_line` | Single-line comments (`#`, `//`, `--`, `;`, etc.) |
| `comment_block` | Multi-line block comments (`/* */`, `{- -}`, etc.) |
| `docstring` | Language docstrings (Python: first string in scope) |
| `string_literal` | All string literal nodes |
| `template_literal` | Template/interpolated strings (JS/TS backtick strings) |

### zone_policy

```yaml
treesitter:
  zone_policy:
    redact_string_literals: true
    min_string_length: 4
```

| Field | Type | Default | Description |
|---|---|---|---|
| `redact_string_literals` | bool | `true` | Whether to include string_literal nodes as zones |
| `min_string_length` | int | `4` | Minimum zone length (bytes) for string literal nodes |

### on_parse_error

```yaml
treesitter:
  on_parse_error: fallback   # "fallback" | "skip" | "fail"
```

| Value | Behavior |
|---|---|
| `fallback` | Return `None` from `extract_zones()`; caller invokes `FallbackExtractor` |
| `skip` | Return `[]`; file is not scanned |
| `fail` | Raise exception; scan of this file is aborted |

### fallback_extractor

```yaml
fallback_extractor:
  enabled: true
  comment_patterns:
    - "^\\s*#.*$"
    - "^\\s*;.*$"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Whether the fallback extractor is available |
| `comment_patterns` | list of strings | `["#.*$", "//.*$", "--.*$"]` | Additional regex patterns (MULTILINE) |

Default patterns cover: `#` (Python, Ruby, Shell), `//` (C-family, JS, Go, Rust), `--` (Lua, SQL).

---

## 7.4 regex/pii_patterns.yaml Schema

### Pattern Entry

```yaml
patterns:
  - name: email
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII
    severity: HIGH
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Unique identifier for this pattern |
| `pattern` | string | Yes | Python regex string (no surrounding `/`) |
| `category` | string | Yes | One of: `PII`, `SECRET`, `ENDPOINT`, `DICTIONARY` |
| `severity` | string | Yes | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |

### Application Scope

Patterns from this file are applied in the following pipeline steps:

| Step | Usage |
|---|---|
| Step 3 (Pre-Scan) | `RegexPIIDetector.detect()` on working tree files |
| Step 5 (Post-Scan) | `RegexPIIDetector.detect()` on redacted working tree |
| Step 6 (History Metadata Scan) | `RegexPIIDetector.detect()` on commit metadata fields |
| Step 6b (History Blob Scan) | `RegexPIIDetector.detect()` on historical blob contents |
| Step 7 (History Rewrite) | Serialized into the filter script's `PII_PATTERNS` list for `message_callback` and `blob_callback` |
| Step 8 / 8b (Post-History Scans) | `RegexPIIDetector.detect()` on rewritten history |

### Masker Selection

The `name` field drives masker selection in `applier.py`'s `_guess_pattern_name()` function. Pattern names with specific prefixes map to specific maskers:

| Pattern `name` contains | Selected masker |
|---|---|
| `email` | `mask_email` |
| `phone` | `mask_phone` |
| `jwt` | `mask_jwt` |
| `https_url`, `url` | `mask_url` |
| `ipv4`, `ip` | `mask_ip` |
| Anything else (by category) | `mask_secret`, `mask_dictionary`, etc. |

### Flag Conventions

- Patterns are compiled with no default flags.
- Case-insensitive matching is enabled inline: `(?i)pattern`.
- Multiline patterns must use `(?m)` or `re.MULTILINE` behavior (not needed for most patterns, which match within a single line).

---

## 7.5 Dictionary Files (dict/*.txt)

Each `.txt` file in the `dict/` directory is loaded into `DictionaryDetector` as a named dictionary. The file stem becomes the dictionary name in findings.

**File format:**

```
# This is a comment line (ignored)
ProjectAlpha
ProjectBeta
OperationSunset
```

- One term per line.
- Lines starting with `#` are ignored.
- Empty lines are ignored.
- Matching is case-insensitive (terms and content are both lowercased).
- Terms may contain spaces and special characters.

**Recommended dictionary files:**

| Filename | Contents |
|---|---|
| `clients.txt` | Client and customer names, including common abbreviations and slugs |
| `codenames.txt` | Internal project and product codenames |
| `orgs.txt` | Internal organizational unit names |
| `domains.txt` | Internal domain names (used by both `DictionaryDetector` and `EndpointDetector`) |

### Dual Use of domains.txt

`dict/domains.txt` is loaded into both:

1. **`DictionaryDetector`** — as string terms for Aho-Corasick matching. Detects the domain name string anywhere in the content.
2. **`EndpointDetector`** — as a custom domain list for structural suffix matching. Detects domain names that structurally end with one of the listed domains.

This redundancy is intentional: the two detectors use different matching strategies and may catch different occurrences of the same domain.

---

## 7.6 Rulepack Versioning

### VERSION File Conventions

The `VERSION` file should contain a semantic version string (`MAJOR.MINOR.PATCH`):

- **PATCH bump:** Adding new dictionary terms, adjusting severity levels, tuning existing patterns.
- **MINOR bump:** Adding new regex patterns, adding new deny_globs, changing allow_suffixes.
- **MAJOR bump:** Removing patterns, changing category/severity assignments, altering core behavior.

### Traceability

The `VERSION` value is recorded in `artifacts/result.json`:

```json
{
  "rulepack_version": "1.2.0",
  "exit_code": 0,
  ...
}
```

This enables audit trails: given a sanitized bundle and its `result.json`, an auditor can reconstruct which rules were in effect during sanitization.

### Governance Recommendations

For shared rulepacks used across an organization:

1. Maintain the rulepack in a dedicated Git repository.
2. Tag each release with the `VERSION` string.
3. Document changes in `CHANGELOG.md`.
4. Require rulepack review as part of the sanitization approval workflow.
5. Pin specific rulepack versions in batch job configurations to ensure reproducibility.
