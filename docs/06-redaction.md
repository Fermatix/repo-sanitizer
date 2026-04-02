# 6. Redaction System

This document describes the masking scheme, the working tree applier, git identity normalization, and the history rewrite mechanism. For the data structures involved, see [02-data-model.md](02-data-model.md). For where these components are invoked, see [03-pipeline.md](03-pipeline.md).

---

## 6.1 Masking Scheme

**Implementation:** `repo_sanitizer/redaction/replacements.py`

### Cryptographic Construction

All sensitive value replacements are derived from HMAC-SHA256:

```python
import hmac

def _hash(salt: bytes, value: str, length: int = 12) -> str:
    return hmac.new(salt, value.encode(), "sha256").hexdigest()[:length]
```

**Why HMAC rather than a plain hash:**
A plain cryptographic hash (SHA-256, SHA-3) is a public function: given the output, an adversary can attempt a rainbow-table attack by precomputing hashes of known sensitive values. HMAC-SHA256 is a keyed construction; its output is cryptographically unpredictable without the secret salt. An adversary who obtains the sanitized output cannot determine whether a given known value was present in the original repository without also obtaining the salt.

**Why 12 hexadecimal characters (48 bits):**
The truncated hash provides 2^48 ≈ 2.8 × 10^14 possible values. Within a single repository, the probability of two distinct values producing the same 12-character suffix is negligible (birthday bound at ~16 million distinct values). The truncation is chosen to balance collision resistance with output readability.

**Determinism property:**
For fixed `salt` and `value`, `_hash(salt, value)` is a pure function. This means:
- The same sensitive value appearing in multiple files or multiple commits always receives the same replacement.
- Two independent runs of the pipeline with the same salt and the same repository produce identical output.
- Cross-repository consistency: the same email address appearing in two repositories sanitized with the same salt receives the same pseudonym, enabling traceability.

### Replacement Functions

All 13 masking functions are defined in `replacements.py`:

| Function | Output format | Example input | Example output | Hash length |
|---|---|---|---|---|
| `mask_email` | `REDACTED_EMAIL_{hash12}` | `alice@corp.internal` | `REDACTED_EMAIL_a1b2c3d4e5f6` | 12 |
| `mask_phone` | `+0000000000` | `+79161234567` | `+0000000000` | — (fixed) |
| `mask_person` | `ANON_PER_{hash12}` | `Alice Smith` | `ANON_PER_a1b2c3d4e5f6` | 12 |
| `mask_org` | `ANON_ORG_{hash12}` | `Acme Corporation` | `ANON_ORG_a1b2c3d4e5f6` | 12 |
| `mask_domain` | `{hash8}.example.invalid` | `corp.internal` | `a1b2c3d4.example.invalid` | 8 |
| `mask_ip` | `REDACTED_IP_{hash12}` | `192.168.1.1` | `REDACTED_IP_a1b2c3d4e5f6` | 12 |
| `mask_secret` | `REDACTED_{hash12}` | `ghp_xxxx...` | `REDACTED_a1b2c3d4e5f6` | 12 |
| `mask_dictionary` | `TERM_{hash12}` | `ProjectPhoenix` | `TERM_a1b2c3d4e5f6` | 12 |
| `mask_endpoint` | `{hash8}.example.invalid` | `srv.corp` | `a1b2c3d4.example.invalid` | 8 |
| `mask_author_name` | `Author_{hash12}` | `Alice Smith` | `Author_a1b2c3d4e5f6` | 12 |
| `mask_author_email` | `author_{hash12}@example.invalid` | `alice@corp.internal` | `author_a1b2c3d4e5f6@example.invalid` | 12 |
| `mask_jwt` | `REDACTED_JWT_{hash12}` | `eyJhbGci...` | `REDACTED_JWT_a1b2c3d4e5f6` | 12 |
| `mask_url` | `REDACTED_URL_{hash12}` | `https://api.internal/v1` | `REDACTED_URL_a1b2c3d4e5f6` | 12 |

**Special case — `mask_phone`:** Phone numbers are replaced with the fixed string `+0000000000` regardless of the input or salt. This is because phone numbers in E.164 format have a known structure that must be preserved in some contexts, and the fixed replacement is both recognizable as a placeholder and valid in format.

**Special case — domain masking:** Domain replacements use an 8-character hash (32 bits) to keep the replacement short enough to remain visually readable, and append `.example.invalid` — a combination that is guaranteed non-resolvable (`.invalid` is an IANA-reserved TLD; `example` is an IANA-reserved second-level domain).

### Masker Selection

The `get_mask()` function selects the appropriate masking function based on detector name and category:

```python
CATEGORY_MASKERS = {
    "email":      mask_email,
    "phone":      mask_phone,
    "phone_e164": mask_phone,
    "person":     mask_person,
    "PER":        mask_person,
    "org":        mask_org,
    "ORG":        mask_org,
    "domain":     mask_domain,
    "ip":         mask_ip,
    "ipv4":       mask_ip,
    "secret":     mask_secret,
    "SECRET":     mask_secret,
    "dictionary": mask_dictionary,
    "DICTIONARY": mask_dictionary,
    "endpoint":   mask_endpoint,
    "ENDPOINT":   mask_endpoint,
    "jwt":        mask_jwt,
    "https_url":  mask_url,
}

def get_mask(salt: bytes, value: str, detector_name: str, category: str) -> str:
    key = detector_name if detector_name in CATEGORY_MASKERS else category
    masker = CATEGORY_MASKERS.get(key)
    if masker:
        return masker(salt, value)
    return f"REDACTED_{_hash(salt, value)}"
```

The lookup first tries `detector_name` (for fine-grained control), then falls back to `category`, and finally uses the generic `REDACTED_{hash}` format if no specific masker is registered.

---

## 6.2 Working Tree Applier

**Implementation:** `repo_sanitizer/redaction/applier.py`

```python
def apply_redactions(
    content: str,
    findings: list[Finding],
    salt: bytes,
) -> tuple[str, list[dict]]:
```

### Reverse-Offset Ordering Invariant

The applier sorts findings by `offset_start` in **descending** order before applying replacements:

```python
sorted_findings = sorted(findings, key=lambda f: f.offset_start, reverse=True)
```

**Correctness proof:**

Let the file content be a string `S` of length `n`. Let findings be `F = {f₁, f₂, ..., fₖ}` sorted such that `f₁.offset_start > f₂.offset_start > ... > fₖ.offset_start`.

When finding `fᵢ` is applied, the replacement produces a new string `S'` such that:
- Characters at positions `< fᵢ.offset_start` are unchanged.
- Characters at positions `≥ fᵢ.offset_end` may shift by `(len(replacement) - len(original))`.

Since we process in descending order, all unprocessed findings `fⱼ` (with `j > i`) have `fⱼ.offset_start < fᵢ.offset_start`. Their positions are in the unchanged region of `S'`. Therefore, their offsets in `S'` are identical to their offsets in `S`.

By induction, applying findings in descending offset order preserves the correctness of all remaining offsets at each step. No offset re-computation is required.

### Span Deduplication

When multiple detectors detect the same byte span (e.g., a JWT token detected by both `SecretsDetector` and `RegexPIIDetector`), the `seen_spans` set prevents double-replacement:

```python
seen_spans: set[tuple[int, int]] = set()

for finding in sorted_findings:
    span = (finding.offset_start, finding.offset_end)
    if span in seen_spans:
        continue
    seen_spans.add(span)
    # apply replacement
```

The first finding in descending-offset order for a given span is applied; subsequent findings for the same span are silently skipped.

### Replacement Selection per Detector

The internal `_get_replacement()` function provides detector-specific masker selection:

```python
def _get_replacement(salt: bytes, finding: Finding) -> str:
    detector = finding.detector
    category = finding.category.value

    if detector == "RegexPIIDetector":
        name = _guess_pattern_name(finding)  # infer from value structure
        return get_mask(salt, finding.matched_value, name, category)

    if detector == "NERDetector":
        if category == "PII":
            return get_mask(salt, finding.matched_value, "PER", category)
        if category == "ORG_NAME":
            return get_mask(salt, finding.matched_value, "ORG", category)

    return get_mask(salt, finding.matched_value, detector, category)
```

The `_guess_pattern_name()` helper infers the most appropriate masker for `RegexPIIDetector` findings by inspecting the value structure:

```python
def _guess_pattern_name(finding: Finding) -> str:
    value = finding.matched_value
    if "@" in value and "." in value:          return "email"
    if value.startswith("+") and value[1:].isdigit(): return "phone_e164"
    if value.startswith("eyJ"):                return "jwt"
    if value.startswith(("http://", "https://")): return "https_url"
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts): return "ipv4"
    return finding.category.value
```

### Manifest Entry Structure

For each applied replacement, one manifest entry is produced:

```python
entry = {
    "detector":      finding.detector,
    "category":      finding.category.value,
    "file_path":     finding.file_path,
    "line":          finding.line,
    "offset_start":  finding.offset_start,
    "offset_end":    finding.offset_end,
    "original_value":original,       # the actual sensitive string
    "replacement":   replacement,    # the pseudonym applied
    "value_hash":    finding.value_hash,
}
# NERDetector findings additionally include:
if finding.detector == "NERDetector":
    entry["ner_label"] = "PER" if finding.category == Category.PII else "ORG"
```

---

## 6.3 Git Identity Normalization

**Implementation:** `repo_sanitizer/redaction/git_identity.py`

```python
def normalize_author(name: str, salt: bytes) -> str:
    return mask_author_name(salt, name)   # → "Author_{hash12}"

def normalize_email(email: str, salt: bytes) -> str:
    return mask_author_email(salt, email) # → "author_{hash12}@example.invalid"
```

These functions are used within the `name_callback` and `email_callback` in the generated history rewrite script (see [§6.4](#64-history-rewrite)).

**Cross-commit consistency:** Because the masking is deterministic, the same author appearing on multiple commits receives the same anonymized name and email across the entire repository history. This preserves authorship relationships (it remains possible to determine which commits were made by the same person) while removing identifying information.

---

## 6.4 History Rewrite

**Implementation:** `repo_sanitizer/steps/history_rewrite.py`

### Self-Contained Script Generation

The history rewrite step generates a Python script that is then executed as a subprocess. The script contains all necessary rule data embedded as Python literals, so it has no runtime dependency on the `repo_sanitizer` package:

```python
script_content = f"""
import re, hmac
import sys
sys.path.insert(0, ...)  # git-filter-repo path

from git_filter_repo import RepoFilter, FilteringOptions

SALT        = {salt_bytes!r}
DENY_GLOBS  = {deny_globs!r}
PII_PATTERNS= [{''.join(f"re.compile({p!r}), " for p in pii_patterns)}]
# ... etc

def _hash(value):
    return hmac.new(SALT, value.encode(), "sha256").hexdigest()[:12]

def name_callback(name):    ...
def email_callback(email):  ...
def message_callback(msg):  ...
def blob_callback(blob):    ...
def filename_callback(fn):  ...

args = FilteringOptions.parse_args(["--force", "--partial", ...])
filter = RepoFilter(args,
    name_callback=name_callback,
    email_callback=email_callback,
    message_callback=message_callback,
    blob_callback=blob_callback,
    filename_callback=filename_callback,
)
filter.run()
"""
```

The generated script is written to `artifacts/_filter_repo_script.py` for audit purposes.

### The Five Callbacks

**`name_callback(name: bytes) -> bytes`**

Replaces every commit author name and committer name:

```python
def name_callback(name):
    h = _hash(name.decode("utf-8", errors="replace"))
    return f"Author_{h}".encode()
```

**`email_callback(email: bytes) -> bytes`**

Replaces every commit author email and committer email:

```python
def email_callback(email):
    h = _hash(email.decode("utf-8", errors="replace"))
    return f"author_{h}@example.invalid".encode()
```

**`message_callback(message: bytes) -> bytes`**

Applies pattern-based replacements to commit message bodies. Each PII pattern match is replaced with a structured token:

```python
def message_callback(message):
    text = message.decode("utf-8", errors="replace")
    for i, pattern in enumerate(PII_PATTERNS):
        def repl(m, idx=i):
            h = _hash(m.group(0))
            return f"[redacted_{idx}:{h}]"
        text = pattern.sub(repl, text)
    return text.encode("utf-8", errors="replace")
```

**`blob_callback(blob) -> None`** (modifies `blob.data` in place)

Applies the same pattern-based replacements to file blob contents. Binary blobs are detected by null-byte check and passed through unchanged:

```python
def blob_callback(blob):
    if b"\x00" in blob.data[:8192]:
        return  # binary: pass through
    try:
        text = blob.data.decode("utf-8", errors="replace")
    except Exception:
        return
    for i, pattern in enumerate(PII_PATTERNS):
        text = pattern.sub(lambda m, idx=i: f"[redacted_{idx}:{_hash(m.group(0))}]", text)
    blob.data = text.encode("utf-8", errors="replace")
```

**`filename_callback(filename: bytes) -> bytes`**

Removes files matching any `deny_glob` pattern from every commit they appear in:

```python
from fnmatch import fnmatchcase

def filename_callback(filename):
    name = filename.decode("utf-8", errors="replace")
    for glob_pat in DENY_GLOBS:
        pat = glob_pat.split("/")[-1]
        if fnmatchcase(name.split("/")[-1], pat):
            return b""  # empty bytes → remove from commit
    return filename
```

Returning `b""` from `filename_callback` instructs git-filter-repo to remove the file from every commit in the rewritten history.

### Git Config Isolation

The history rewrite subprocess is executed with an isolated git configuration:

```python
env = os.environ.copy()
env["GIT_CONFIG_NOSYSTEM"] = "1"
env["GIT_CONFIG_SYSTEM"]   = os.devnull
env["GIT_CONFIG_GLOBAL"]   = os.devnull
```

**Rationale:** `git-filter-repo` internally calls `git config --list` to read git configuration. If the operator's global `~/.gitconfig` contains multiline values (e.g., credential helpers configured with newline-separated arguments in some git versions), the resulting output contains embedded newlines that cannot be parsed by filter-repo's Python config parser, causing a crash. Setting all config paths to `/dev/null` ensures that no user or system configuration is read during the rewrite.

### Single-Pass Efficiency

All five callbacks are registered in a single `RepoFilter` instance and applied in one pass over the repository's object store. This is O(history_size) rather than O(5 × history_size) — the object store is traversed once, and all transformations are applied to each object simultaneously.

---

## 6.5 Redaction Scope Matrix

| What is redacted | Mechanism | Pipeline step | Scope |
|---|---|---|---|
| File contents (current) | `apply_redactions()` (reverse-offset) | Step 4 (Redact) | Working tree at `--rev` |
| Files matching deny_globs | File deletion | Step 4 (Redact) | Working tree at `--rev` |
| Commit author names | `name_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
| Commit author emails | `email_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
| Commit committer names | `name_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
| Commit committer emails | `email_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
| Commit message bodies | `message_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
| Historical file blob contents | `blob_callback` in filter script | Step 7 (History Rewrite) | All unique blobs on all branches/tags |
| Historical deny-glob files | `filename_callback` in filter script | Step 7 (History Rewrite) | All commits on all branches/tags |
