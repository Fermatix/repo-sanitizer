# 4. Detection Subsystem

This document describes the five detectors that form the core of the repo-sanitizer scanning engine. For the data structures they produce, see [02-data-model.md](02-data-model.md). For how detectors are invoked within the pipeline, see [03-pipeline.md](03-pipeline.md).

---

## 4.1 Detector Interface

All detectors are implemented as concrete subclasses of the abstract base class `Detector` (defined in `repo_sanitizer/detectors/base.py`):

```python
class Detector(ABC):
    @abstractmethod
    def detect(self, target: ScanTarget) -> list[Finding]:
        ...
```

### Statelesness

Detectors hold no mutable state with respect to the files they process. All detection logic is applied independently to each `ScanTarget`. The sole exception is `NERDetector`, which lazily loads its ML model on first use; the model parameters are immutable once loaded.

### Zone-Awareness Contract

For detectors that support zones, a match at byte interval `[ms, me)` is included in the result only if there exists a zone `z ∈ target.zones` such that:

```
z.start ≤ ms  AND  me ≤ z.end
```

When `target.zones is None`, detectors scan the entire content without restriction.

The implementation pattern used across multiple detectors:

```python
def _in_zones(self, start: int, end: int, zones: list[Zone]) -> bool:
    return any(z.start <= start and end <= z.end for z in zones)
```

---

## 4.2 SecretsDetector

**Implementation:** `repo_sanitizer/detectors/secrets.py`

**Category:** `SECRET`  **Severity:** `CRITICAL`

### Architecture

`SecretsDetector` is a wrapper around the `gitleaks` CLI tool. For each `ScanTarget`, it:

1. Writes the content (or zone-restricted content) to a temporary file.
2. Spawns a subprocess: `gitleaks detect --no-git --source <tmpdir> --report-format json --report-path <report>`.
3. Parses the JSON report output.
4. Maps gitleaks findings to `Finding` objects, computing byte offsets from (line, column) pairs using `_find_offset()`.

```python
def _find_offset(content: str, line: int, col: int) -> int:
    lines = content.split("\n")
    offset = sum(len(lines[i]) + 1 for i in range(line - 1))
    return offset + col
```

### Zone Handling

For zone-restricted targets, the temporary file contains only the bytes within each zone, with offsets recorded so that found positions can be mapped back to the original content coordinates.

### Initialization Guard

```python
def __init__(self):
    if not shutil.which("gitleaks"):
        raise RuntimeError("gitleaks not found in PATH. Install gitleaks to use SecretsDetector.")
```

This check runs at detector instantiation (Step 3 of the pipeline), before any files are scanned.

### Exclusion from Blob Scan

`SecretsDetector` is excluded from the history blob scan (Step 6b) because it spawns a subprocess per invocation. For a repository with 10,000 unique blobs, this would require 10,000 gitleaks process launches, introducing unacceptable latency. The `build_history_detectors()` function (see [§4.7](#47-detector-composition)) explicitly omits it.

---

## 4.3 RegexPIIDetector

**Implementation:** `repo_sanitizer/detectors/regex_pii.py`

### Algorithm

```python
for pattern in self.patterns:
    for match in pattern.compiled.finditer(content):
        if target.is_zoned and not _in_zones(match.start(), match.end(), target.zones):
            continue
        line = content[:match.start()].count("\n") + 1
        findings.append(Finding(
            detector="RegexPIIDetector",
            category=pattern.category,
            severity=pattern.severity,
            file_path=target.file_path,
            line=line,
            offset_start=match.start(),
            offset_end=match.end(),
            matched_value=match.group(0),
        ))
```

### Pattern Taxonomy

The default rulepack (`examples/rules/regex/pii_patterns.yaml`) defines the following patterns:

**PII Patterns:**

| Name | Category | Severity | Description | Example match |
|---|---|---|---|---|
| `email` | PII | HIGH | Generic email address (excludes `.invalid` TLD) | `alice@company.com` |
| `phone_e164` | PII | HIGH | E.164 international format | `+12025550100` |
| `phone_ru` | PII | HIGH | Russian national formats | `+7 (495) 123-45-67` |
| `ipv4` | ENDPOINT | MEDIUM | IPv4 address (4 octets) | `192.168.1.1` |
| `ipv4_with_port` | ENDPOINT | MEDIUM | IPv4 with port | `10.0.0.1:8080` |
| `ssn` | PII | HIGH | US Social Security Number | `123-45-6789` |
| `credit_card` | PII | HIGH | Visa/Mastercard/Amex/Discover | `4111111111111111` |
| `iban` | PII | HIGH | International Bank Account Number | `GB29NWBK60161331926819` |
| `passport_ru` | PII | HIGH | Russian passport series + number | `1234 567890` |
| `inn_ru` | PII | HIGH | Russian INN (tax identification) | `7743013901` |

**Secret Patterns:**

| Name | Category | Severity | Description | Example match |
|---|---|---|---|---|
| `jwt` | SECRET | CRITICAL | JWT token (header.payload.signature) | `eyJhbGciOiJIUzI1NiJ9.e...` |
| `pem_private_key` | SECRET | CRITICAL | PEM-encoded private key header | `-----BEGIN RSA PRIVATE KEY-----` |
| `aws_access_key_id` | SECRET | CRITICAL | AWS access key (AKIA/ASIA/AROA prefixes) | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | SECRET | CRITICAL | AWS secret access key assignment | `aws_secret_access_key=wJalrXUtnFEMI/K7MDENG` |
| `github_token` | SECRET | CRITICAL | GitHub PAT (ghp_/ghs_/ghu_/ghr_) | `ghp_16C7e42F292c6912E7710c838347Ae178B4a` |
| `github_pat_v2` | SECRET | CRITICAL | GitHub fine-grained PAT | `github_pat_11AABCD...` |
| `gitlab_token` | SECRET | CRITICAL | GitLab PAT | `glpat-xxxxxxxxxxxxxxxxxxxx` |
| `slack_token` | SECRET | CRITICAL | Slack API token | `xoxb-123456-...` |
| `slack_webhook` | SECRET | CRITICAL | Slack incoming webhook URL | `hooks.slack.com/services/T.../B.../...` |
| `stripe_live_key` | SECRET | CRITICAL | Stripe live secret key | `sk_live_...` |
| `stripe_test_key` | SECRET | HIGH | Stripe test secret key | `sk_test_...` |
| `stripe_publishable_key` | SECRET | MEDIUM | Stripe publishable key | `pk_live_...` |
| `sendgrid_api_key` | SECRET | CRITICAL | SendGrid API key | `SG.xxxxxxxx.xxxxxxxx` |
| `google_api_key` | SECRET | CRITICAL | Google API key | `AIzaSy...` |
| `google_oauth_token` | SECRET | CRITICAL | Google OAuth token | `ya29.a0A...` |
| `npm_token` | SECRET | CRITICAL | npm registry token | `npm_xxxxxxxxxxxx` |
| `pypi_token` | SECRET | CRITICAL | PyPI API token | `pypi-AgEI...` |
| `twilio_sid` | SECRET | CRITICAL | Twilio Account SID | `ACxxxxxxxxxxxxxxxx...` |
| `mailchimp_api_key` | SECRET | CRITICAL | Mailchimp API key | `xxxxxxxxxxxxxx-us1` |
| `telegram_bot_token` | SECRET | CRITICAL | Telegram bot token | `1234567890:AAxxxxxxx...` |
| `generic_api_key` | SECRET | HIGH | Heuristic key=value assignment | `api_key = "secret123"` |
| `basic_auth_in_url` | SECRET | CRITICAL | Credentials embedded in URL | `https://user:pass@api.example.com` |

**Endpoint Patterns (via RegexPII):**

| Name | Category | Severity | Description |
|---|---|---|---|
| `https_url` | ENDPOINT | MEDIUM | HTTP/HTTPS URL |
| `db_connection_*` | ENDPOINT | HIGH | Database connection strings (postgres, mysql, mongodb, redis, amqp) |
| `jdbc_url` | ENDPOINT | HIGH | JDBC connection string |
| `internal_corp_url` | ENDPOINT | HIGH | URL with internal TLD |

**Dictionary Patterns (via RegexPII):**

| Name | Category | Severity | Description |
|---|---|---|---|
| `jira_ticket` | DICTIONARY | MEDIUM | Jira ticket reference (e.g., `PROJ-1234`) |
| `github_issue_ref` | DICTIONARY | LOW | GitHub issue reference (`#123`, `org/repo#123`) |
| `uuid` | DICTIONARY | LOW | UUID v4 format |

---

## 4.4 DictionaryDetector

**Implementation:** `repo_sanitizer/detectors/dictionary.py`

**Category:** `DICTIONARY`  **Severity:** `HIGH`

### Algorithm: Aho-Corasick Automaton

```python
import ahocorasick

def __init__(self, dictionaries: dict[str, list[str]]):
    self.automaton = ahocorasick.Automaton()
    for dict_name, terms in dictionaries.items():
        for term in terms:
            key = term.lower()  # case-fold for case-insensitive matching
            if key not in self.automaton:
                self.automaton[key] = []
            self.automaton[key].append((dict_name, term))
    self.automaton.make_automaton()
```

Detection is performed by iterating over the automaton:

```python
content_lower = content.lower()
for end_idx, (dict_name, original_term) in self.automaton.iter(content_lower):
    start_idx = end_idx - len(original_term) + 1
    if target.is_zoned and not _in_zones(start_idx, end_idx + 1, target.zones):
        continue
    # emit Finding with matched_value = content[start_idx:end_idx+1]
```

The original-case matched string is recovered from `content[start_idx:end_idx+1]` (not from the lowercased copy), preserving case information in the finding.

### Complexity Analysis

| Approach | Construction | Search |
|---|---|---|
| Aho-Corasick | O(m) where m = total term characters | O(n + z) where n = text length, z = match count |
| Naive (per-term `str.find`) | O(1) | O(n × k) where k = dictionary size |

For a dictionary of 10,000 terms (total 150,000 characters) searching a 100 KB file:
- Naive: ~10^9 character comparisons
- Aho-Corasick: ~10^5 character comparisons (+ small constant overhead per match)

### Multi-Dictionary Support

Multiple `.txt` files from the rulepack `dict/` directory are each loaded under their stem name (e.g., `clients.txt` → `"clients"`). The stem name is recorded in the finding for auditability, enabling analysts to identify which dictionary category produced a given match.

---

## 4.5 EndpointDetector

**Implementation:** `repo_sanitizer/detectors/endpoint.py`

**Category:** `ENDPOINT`

### Sub-Mechanism 1: Private IPv4 Detection

```python
_IPV4_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

for match in _IPV4_RE.finditer(content):
    try:
        addr = ipaddress.ip_address(match.group(0))
        if not addr.is_private:
            continue
    except ValueError:
        continue
    # emit Finding(severity=MEDIUM)
```

RFC 1918 private ranges detected: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. The `ipaddress.is_private` property additionally covers loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and IPv4-mapped addresses.

### Sub-Mechanism 2: Internal Domain Detection

```python
_DOMAIN_RE = re.compile(
    r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_INTERNAL_TLDS = {".internal", ".corp", ".local", ".lan", ".intra"}

for match in _DOMAIN_RE.finditer(content):
    domain = match.group(0).lower()
    is_internal = any(domain.endswith(tld) for tld in _INTERNAL_TLDS)
    is_custom   = any(domain.endswith("." + d.lower()) or domain == d.lower()
                      for d in self.domain_list)
    if not (is_internal or is_custom):
        continue
    # emit Finding(severity=HIGH)
```

Custom domains from `dict/domains.txt` are passed to `EndpointDetector` as `domain_list` and checked as suffixes.

**Note on overlap with DictionaryDetector:** Domains from `dict/domains.txt` are simultaneously loaded into both `DictionaryDetector` (as string terms for Aho-Corasick matching) and `EndpointDetector` (for structural suffix matching). This intentional redundancy ensures that both exact string matches and domain-structure matches are detected independently.

---

## 4.6 NERDetector

**Implementation:** `repo_sanitizer/detectors/ner.py`

Named Entity Recognition maps detected named entities to findings:

| NER Label | Category | Severity |
|---|---|---|
| `PER` (person name) | `PII` | `HIGH` |
| `ORG` (organization) | `ORG_NAME` | `MEDIUM` |

### Backends

**HuggingFace Transformers (`backend: hf`):**

```python
from transformers import pipeline as hf_pipeline
self.pipe = hf_pipeline(
    "ner",
    model=config.model,
    aggregation_strategy="simple",
    device=resolved_device,
)
```

Default model: `Davlan/bert-base-multilingual-cased-ner-hrl` (multilingual BERT, supports 10+ languages).

**GLiNER (`backend: gliner`):**

```python
from gliner import GLiNER
self.model = GLiNER.from_pretrained(config.model)
```

GLiNER uses descriptive English phrases as labels (e.g., `"person name"`, `"organization name"`) and performs zero-shot entity recognition without requiring token-level training for each entity type. It does not require `torch` as a dependency, making it suitable for CPU-only deployments.

### Text Chunking Algorithm

Large files are split into overlapping chunks to stay within the model's token window:

```
CHUNK_MAX_CHARS = 2000
LINE_MAX_CHARS  = 2000
CHUNK_OVERLAP_LINES = 3

1. Split content into lines.
2. For each line exceeding LINE_MAX_CHARS:
   - Split on the last whitespace before the limit (hard-cut if no whitespace).
3. Accumulate lines into chunks:
   - While chunk length + next line ≤ CHUNK_MAX_CHARS: append line to chunk.
   - When limit reached: finalize chunk, begin new chunk with the last
     CHUNK_OVERLAP_LINES lines of the previous chunk.
4. Track the byte offset of each chunk's first character relative to content start.
```

The 3-line overlap ensures that entities spanning a chunk boundary are detected completely by at least one chunk.

### HTTP Service Mode

When `ctx.ner_service_url` is set (batch processing), `NERDetector` sends all chunks as a single HTTP batch request:

```python
response = requests.post(
    f"{service_url}/ner",
    json={"texts": [chunk.text for chunk in chunks]},
    timeout=120,
)
results = response.json()["results"]
```

Retry policy: 3 retries with delays of 2s, 5s, and 10s on connection errors or 5xx responses.

### Deduplication

Multiple chunks may detect the same entity (due to the overlap). `_deduplicate()` removes findings with identical `(offset_start, offset_end)` pairs, keeping the first occurrence:

```python
def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for f in findings:
        key = (f.offset_start, f.offset_end)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
```

### Device Resolution

```python
def _resolve_device(device: str) -> str:
    if device == "auto":
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    if device.startswith("cuda"):
        import torch
        if not torch.cuda.is_available():
            logger.warning("CUDA not available, falling back to CPU")
            return "cpu"
    return device
```

### Exclusion from Blob Scan

`NERDetector` is excluded from the history blob scan for two reasons:
1. Local inference: model forward passes are expensive; running one pass per blob (potentially thousands) is impractical.
2. HTTP service mode: the service receives one batch request per file, not per blob. At the per-blob level, the amortization benefit is lost.

---

## 4.7 Detector Composition

### build_detectors() — Working Tree and History Metadata Scans

```python
def build_detectors(rulepack: Rulepack, ner_service_url: str | None) -> list[Detector]:
    detectors = [SecretsDetector()]
    if rulepack.pii_patterns:
        detectors.append(RegexPIIDetector(rulepack.pii_patterns))
    if any(v for v in rulepack.dictionaries.values()):
        detectors.append(DictionaryDetector(rulepack.dictionaries))
    domain_list = rulepack.dictionaries.get("domains", [])
    detectors.append(EndpointDetector(domain_list))
    if rulepack.ner_config:
        detectors.append(NERDetector(rulepack.ner_config, ner_service_url))
    return detectors
```

Used in Steps 3, 5, 6, and 8.

### build_history_detectors() — History Blob Scans

```python
def build_history_detectors(rulepack: Rulepack) -> list[Detector]:
    """SecretsDetector and NERDetector excluded: subprocess per blob is
    prohibitively slow for large histories."""
    detectors = []
    if rulepack.pii_patterns:
        detectors.append(RegexPIIDetector(rulepack.pii_patterns))
    if any(v for v in rulepack.dictionaries.values()):
        detectors.append(DictionaryDetector(rulepack.dictionaries))
    domain_list = rulepack.dictionaries.get("domains", [])
    detectors.append(EndpointDetector(domain_list))
    return detectors
```

Used in Steps 6b and 8b.

### Rationale for the Reduced Set

The exclusion of `SecretsDetector` and `NERDetector` from blob scans is an explicit performance trade-off. Secret detection in the working tree (Step 3) and commit metadata (Step 6) provides coverage for the most common attack surface. The history blob scan provides additional coverage for PII, corporate terms, and internal endpoints that may appear in historical file contents without being present in the current working tree.
