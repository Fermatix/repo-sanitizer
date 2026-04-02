# 2. Core Data Model

This document provides the canonical definitions of all data structures used throughout the repo-sanitizer pipeline. All other documents in this suite reference these definitions rather than redefining them locally.

---

## 2.1 Severity and Category Enumerations

Defined in `repo_sanitizer/detectors/base.py`.

### Severity

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
```

| Value | Semantic meaning |
|---|---|
| `CRITICAL` | Must be addressed before delivery; pipeline gate blocks on any remaining finding |
| `HIGH` | Blocks delivery when found in PII category (gate `PII_HIGH`) |
| `MEDIUM` | Reported but does not block via a standard gate |
| `LOW` | Informational; no gate blocks on LOW findings |
| `INFO` | Diagnostic; not evaluated by any gate |

### Category

```python
class Category(str, Enum):
    SECRET     = "SECRET"
    PII        = "PII"
    ORG_NAME   = "ORG_NAME"
    DICTIONARY = "DICTIONARY"
    ENDPOINT   = "ENDPOINT"
```

| Value | Semantic meaning | Producing detectors |
|---|---|---|
| `SECRET` | Cryptographic credentials and API tokens | `SecretsDetector`, `RegexPIIDetector` (pattern-dependent) |
| `PII` | Personally Identifiable Information | `RegexPIIDetector`, `NERDetector` (entity label `PER`) |
| `ORG_NAME` | Named organizational entities | `NERDetector` (entity label `ORG`) |
| `DICTIONARY` | Organization-specific sensitive terms | `DictionaryDetector` |
| `ENDPOINT` | Internal infrastructure identifiers | `EndpointDetector` |

---

## 2.2 Finding

```python
@dataclass
class Finding:
    detector:      str       # class name of the producing detector
    category:      Category
    severity:      Severity
    file_path:     str       # relative path or virtual path (see §2.2.1)
    line:          int       # 1-based line number within the file/blob
    offset_start:  int       # byte offset within decoded UTF-8 content (inclusive)
    offset_end:    int       # byte offset within decoded UTF-8 content (exclusive)
    matched_value: str = field(repr=False)  # the raw detected string
    value_hash:    str = ""  # populated by compute_hash()
```

### 2.2.1 Virtual File Paths

For findings in commit metadata or historical blobs, `file_path` uses a structured virtual path format that encodes the origin:

| Scan scope | Path format | Example |
|---|---|---|
| Working tree | Relative POSIX path | `src/config/settings.py` |
| Commit metadata field | `<commit:{sha8}/{field}>` | `<commit:a1b2c3d4/author_email>` |
| Historical blob | `<history:{sha8}/{path}>` | `<history:a1b2c3d4/src/config/settings.py>` |

### 2.2.2 Methods

**`compute_hash(salt: bytes) -> None`**

Computes and stores the `value_hash` field:

```python
def compute_hash(self, salt: bytes) -> None:
    self.value_hash = hmac.new(
        salt, self.matched_value.encode(), "sha256"
    ).hexdigest()[:12]
```

This is a keyed one-way function. Given only `value_hash` and without the salt, the original `matched_value` cannot be recovered.

**`to_report() -> dict`**

Serializes the finding for inclusion in JSON scan report artifacts. **`matched_value` is deliberately excluded** from this output:

```python
def to_report(self) -> dict:
    return {
        "detector":     self.detector,
        "category":     self.category.value,
        "severity":     self.severity.value,
        "file_path":    self.file_path,
        "line":         self.line,
        "offset_start": self.offset_start,
        "offset_end":   self.offset_end,
        "value_hash":   self.value_hash,
    }
```

### 2.2.3 Security Invariant

The `matched_value` field is declared with `repr=False` in the dataclass definition. This prevents the sensitive value from appearing in:

- Log output (Python's default `logging` formats use `repr()`)
- Exception tracebacks that print the dataclass
- Any automatic serialization that iterates dataclass fields

The `matched_value` is written to disk exactly once: in `artifacts/redaction_manifest.json` via the `original_value` key (see [§2.8](#28-json-report-schemas)), which is a local artifact not included in the output bundle.

---

## 2.3 Zone

```python
@dataclass
class Zone:
    start: int   # inclusive byte offset
    end:   int   # exclusive byte offset
```

A `Zone` defines a contiguous half-open interval `[start, end)` within the decoded UTF-8 string content of a file. Detectors that respect zones only emit findings whose span `[offset_start, offset_end)` falls within at least one zone (see [§4.1](04-detection.md#41-detector-interface)).

### Zone Semantics

- `zones is None` — the file is not zone-restricted; detectors scan the entire content. Used for DOCS and CONFIG category files, and for all historical blob scans.
- `zones = []` (empty list) — the file was recognized as CODE but contains no scannable regions (e.g., a file consisting entirely of identifier-only code). Detectors produce no findings.
- `zones = [Zone(...), ...]` — detectors operate only within the listed intervals.

---

## 2.4 ScanTarget

```python
@dataclass
class ScanTarget:
    file_path: str
    content:   str
    zones:     Optional[list[Zone]] = None

    @property
    def is_zoned(self) -> bool:
        return self.zones is not None
```

`ScanTarget` is the unit of work passed to every detector's `detect()` method. It encapsulates:

- `file_path` — used for logging and for the `Finding.file_path` field; may be a virtual path for history scans.
- `content` — the full decoded UTF-8 string content of the file or blob.
- `zones` — optional list of scannable intervals; `None` means scan everything.

### Detector Contract

If `target.is_zoned` is `True`, detectors **must** only emit findings whose span `[offset_start, offset_end)` is contained within at least one `Zone` in `target.zones`. Specifically, for a match at interval `[ms, me)`, there must exist a zone `z` such that `z.start <= ms` and `me <= z.end`.

---

## 2.5 InventoryItem

```python
@dataclass
class InventoryItem:
    path:     str           # POSIX path relative to work_dir
    size:     int           # file size in bytes
    mime:     str           # MIME type string
    category: FileCategory
    action:   FileAction
    reason:   str = ""      # human-readable explanation of the action decision
```

### FileCategory

```python
class FileCategory(str, Enum):
    CODE   = "code"
    CONFIG = "config"
    DOCS   = "docs"
    BINARY = "binary"
```

| Value | Classification criteria |
|---|---|
| `CODE` | File extension in CODE_EXTENSIONS set (`.py`, `.js`, `.ts`, `.java`, `.go`, `.rs`, etc.) |
| `CONFIG` | File extension or name matching CONFIG patterns (`.env`, `.yaml`, `.toml`, `.ini`, `codeowners`) |
| `DOCS` | File extension in DOCS set (`.md`, `.rst`, `.txt`, `.json`, `.xml`, `.csv`) |
| `BINARY` | All others; confirmed by null-byte detection or extension-based MIME classification |

`FileCategory` determines whether zone extraction is performed during scanning: only `CODE` files have zones extracted; all other categories are scanned in full.

### FileAction

```python
class FileAction(str, Enum):
    SCAN   = "SCAN"
    DELETE = "DELETE"
    SKIP   = "SKIP"
```

| Value | Meaning |
|---|---|
| `SCAN` | Include in scan and (if the sanitize pipeline is running) apply redactions |
| `DELETE` | Remove from the working tree during redaction; excluded from the output bundle |
| `SKIP` | Do not scan (too large, binary format, or binary extension in allow-list) |

### Allow-Suffix Stripping Mechanism

Files whose names match a `deny_glob` pattern from the rulepack (see [§7.2](07-configuration.md#72-policiesyaml-schema)) receive `FileAction.DELETE` — unless their name ends with one of the configured `allow_suffixes`.

The suffix check is applied to the **base name with the allow-suffix stripped**:

```
.env.example → strip ".example" → base name ".env" → matches deny_glob "**/.env" → action SCAN (not DELETE)
```

This permits template files (`.env.example`, `config.yaml.template`) to be scanned for secrets rather than deleted, since they are commonly committed intentionally.

### to_dict() Contract

```python
def to_dict(self) -> dict:
    return {
        "path":     self.path,
        "size":     self.size,
        "mime":     self.mime,
        "category": self.category.value,
        "action":   self.action.value,
        "reason":   self.reason,
    }
```

---

## 2.6 RunContext

`RunContext` is the central state object that threads through every pipeline step. It is created once at pipeline startup and mutated in place as each step completes.

```python
@dataclass
class RunContext:
    salt:                      bytes
    work_dir:                  Path
    out_dir:                   Path
    artifacts_dir:             Path
    rulepack_path:             Path
    rulepack:                  object = None         # Rulepack, populated in Step 0
    inventory:                 list[InventoryItem] = field(default_factory=list)
    pre_findings:              list[Finding]       = field(default_factory=list)
    post_findings:             list[Finding]       = field(default_factory=list)
    history_pre_findings:      list[Finding]       = field(default_factory=list)
    history_post_findings:     list[Finding]       = field(default_factory=list)
    history_blob_pre_findings: list[Finding]       = field(default_factory=list)
    history_blob_post_findings:list[Finding]       = field(default_factory=list)
    redaction_manifest:        list[dict]          = field(default_factory=list)
    timings:                   dict                = field(default_factory=dict)
    rev:                       str = "HEAD"
    max_file_mb:               int = 20
    history_since:             Optional[str] = None
    history_until:             Optional[str] = None
    ner_service_url:           Optional[str] = None
```

### Field Population by Pipeline Step

| Field | Populated by step | Notes |
|---|---|---|
| `salt` | `create()` factory | Derived from `REPO_SANITIZER_SALT` env var |
| `work_dir`, `out_dir`, `artifacts_dir` | `create()` factory | Directories created on disk |
| `rulepack` | Step 0 (config load) | `load_rulepack(ctx.rulepack_path)` |
| `inventory` | Step 2 (Inventory) | One `InventoryItem` per non-`.git` file |
| `pre_findings` | Step 3 (Pre-Scan) | Working tree findings before redaction |
| `redaction_manifest` | Step 4 (Redact) | One entry per applied replacement |
| `post_findings` | Step 5 (Post-Scan) | Working tree findings after redaction |
| `history_pre_findings` | Step 6 (History Metadata Scan) | Commit metadata findings |
| `history_blob_pre_findings` | Step 6b (History Blob Scan) | Blob findings before history rewrite |
| `history_post_findings` | Step 8 (History Metadata Post-Scan) | Commit metadata after rewrite |
| `history_blob_post_findings` | Step 8b (History Blob Post-Scan) | Blob findings after history rewrite |
| `timings` | Accumulated throughout | Per-step and per-detector timings |

### create() Factory

```python
@classmethod
def create(cls, source, out_dir, rulepack_path,
           salt_env="REPO_SANITIZER_SALT", ...) -> RunContext:
    salt_value = os.environ.get(salt_env, "")
    if not salt_value:
        raise ValueError(...)
    out = Path(out_dir).expanduser().resolve()
    (out / "work").mkdir(parents=True, exist_ok=True)
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    (out / "output").mkdir(parents=True, exist_ok=True)
    return cls(salt=salt_value.encode(), ...)
```

The factory validates salt presence before creating any directories. Salt is sourced exclusively from an environment variable to prevent exposure in shell history, process lists, or `/proc/*/cmdline`.

### ner_service_url Field

When set, `NERDetector` sends HTTP requests to the specified service URL instead of loading the NER model in-process. This is the primary mechanism for the batch processing mode's shared GPU inference architecture (see [§8.2](08-batch-processing.md#82-ner-http-service)).

---

## 2.7 Rulepack Data Model

Defined in `repo_sanitizer/rulepack.py`. Loaded by `load_rulepack(path: Path) -> Rulepack`.

```python
@dataclass
class PIIPattern:
    name:     str
    pattern:  re.Pattern   # compiled regex
    category: Category
    severity: Severity
```

```python
@dataclass
class ExtractorLanguage:
    id:               str        # e.g. "python", "typescript"
    grammar_package:  str        # Python package providing the grammar
    file_extensions:  list[str]  # e.g. [".py", ".pyw"]
    extract_zones:    list[str]  # e.g. ["comment_line", "docstring", "string_literal"]
```

```python
@dataclass
class NERConfig:
    backend:      str         # "hf" or "gliner"
    model:        str         # HuggingFace model ID
    min_score:    float       # confidence threshold (0.0–1.0)
    entity_types: list[str]   # e.g. ["PER", "ORG"]
    device:       str         # "cpu", "cuda", "cuda:0", "auto"
```

```python
@dataclass
class Rulepack:
    version:               str
    deny_globs:            list[str]       # fnmatch patterns
    allow_suffixes:        list[str]       # e.g. [".example", ".template"]
    binary_deny_extensions:set[str]        # extensions to delete
    binary_allow_extensions:set[str]       # extensions to keep (skip scanning)
    max_file_mb:           int
    pii_patterns:          list[PIIPattern]
    dictionaries:          dict[str, list[str]]  # stem → list of terms
    extractor_config:      ExtractorConfig
    ner_config:            NERConfig
```

---

## 2.8 JSON Report Schemas

### scan_report_pre.json / scan_report_post.json / history_*.json

Array of `Finding.to_report()` objects:

```json
[
  {
    "detector":     "RegexPIIDetector",
    "category":     "PII",
    "severity":     "HIGH",
    "file_path":    "src/config.py",
    "line":         42,
    "offset_start": 1024,
    "offset_end":   1048,
    "value_hash":   "a1b2c3d4e5f6"
  }
]
```

Note: `matched_value` is **absent** from all scan reports.

### inventory.json

Array of `InventoryItem.to_dict()` objects:

```json
[
  {
    "path":     "src/config.py",
    "size":     4096,
    "mime":     "text/x-python",
    "category": "code",
    "action":   "SCAN",
    "reason":   "code file"
  }
]
```

### redaction_manifest.json

Array of redaction entries. This is the **only** artifact that records original values:

```json
[
  {
    "detector":      "RegexPIIDetector",
    "category":      "PII",
    "file_path":     "src/config.py",
    "line":          42,
    "offset_start":  1024,
    "offset_end":    1048,
    "original_value":"alice@corp.internal",
    "replacement":   "REDACTED_EMAIL_a1b2c3d4e5f6",
    "value_hash":    "a1b2c3d4e5f6"
  }
]
```

This file remains in `artifacts/` (local output) and is never included in `output/sanitized.bundle`.

### result.json

```json
{
  "exit_code": 0,
  "all_passed": true,
  "gates": {
    "SECRETS":        {"passed": true,  "description": "...", "failing_count": 0},
    "PII_HIGH":       {"passed": true,  "description": "...", "failing_count": 0},
    "DICTIONARY":     {"passed": true,  "description": "...", "failing_count": 0},
    "ENDPOINTS":      {"passed": true,  "description": "...", "failing_count": 0},
    "FORBIDDEN_FILES":{"passed": true,  "description": "...", "failing_count": 0, "files": []},
    "CONFIGS":        {"passed": true,  "description": "...", "failing_count": 0, "files": []}
  },
  "summary": {
    "total_pre_findings":              42,
    "total_post_findings":             0,
    "total_history_pre_findings":      15,
    "total_history_post_findings":     0,
    "total_history_blob_pre_findings": 8,
    "total_history_blob_post_findings":0,
    "total_redactions":                65
  },
  "timings": {
    "steps": {
      "fetch":          2.345,
      "inventory":      0.123,
      "scan_pre":       15.678,
      "redact":         0.456,
      "scan_post":      12.234,
      "history_scan":   3.456,
      "history_blob":   45.678,
      "history_rewrite":8.901,
      "gate":           0.012,
      "package":        1.234
    },
    "detectors": {
      "scan_pre": {
        "SecretsDetector":   10.100,
        "RegexPIIDetector":  1.200,
        "DictionaryDetector":0.300,
        "EndpointDetector":  0.200,
        "NERDetector":       3.878
      }
    },
    "gates": {
      "SECRETS": 0.001, "PII_HIGH": 0.001, "DICTIONARY": 0.001,
      "ENDPOINTS": 0.001, "FORBIDDEN_FILES": 0.002, "CONFIGS": 0.003
    },
    "total_s": 89.456
  },
  "bundle_sha256": "abcdef1234567890...",
  "bundle_path":   "/absolute/path/to/output/sanitized.bundle"
}
```
