# Rulepack authoring

A rulepack is a directory that fully defines what counts as sensitive data and how to handle it.

Full example with all fields and comments: `examples/full-rulepack/`.

---

## Minimal rulepack

```bash
mkdir -p my-rules/{dict,regex}

# Required version file
echo "1.0.0" > my-rules/VERSION

# Minimal policies
cat > my-rules/policies.yaml << 'EOF'
deny_globs:
  - "**/.env"
  - "**/*.key"
  - "**/*.pem"

allow_suffixes: [".example", ".sample", ".template"]

binary_deny_extensions: [exe, dll, zip, db]
binary_allow_extensions: [png, jpg, gif, svg]

max_file_mb: 20
EOF

# Minimal extractors
cat > my-rules/extractors.yaml << 'EOF'
treesitter:
  languages:
    - id: python
      grammar_package: tree-sitter-python
      file_extensions: [.py]
      extract_zones: [comment_line, docstring, string_literal]
  zone_policy:
    redact_string_literals: true
    min_string_length: 4
  on_parse_error: fallback

fallback_extractor:
  enabled: true
  comment_patterns:
    - pattern: '#.*$'
    - pattern: '//.*$'
EOF

# Minimal regex patterns
cat > my-rules/regex/pii_patterns.yaml << 'EOF'
patterns:
  - name: email
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII
    severity: HIGH
EOF

# Empty dictionaries
touch my-rules/dict/domains.txt
touch my-rules/dict/orgs.txt
touch my-rules/dict/clients.txt
touch my-rules/dict/codenames.txt
```

---

## policies.yaml — full schema

### deny_globs

`fnmatch`-style glob patterns. A file that matches a deny glob:
- is **deleted** (`DELETE`) if it has no allowed suffix
- is **scanned** (`SCAN`) if its suffix is in `allow_suffixes`

Matching uses the **base name with the allow-suffix stripped**. For example, `.env.template` matches `**/.env` and gets action `SCAN`.

```yaml
deny_globs:
  - "**/.env"           # any .env file in any directory
  - "**/config.*"       # config.yaml, config.prod.json, …
  - "**/secrets.*"
  - "**/*.key"
  - "**/*.pem"
  - "**/.mailmap"
  - "**/CODEOWNERS"
```

### allow_suffixes

Suffixes that allow a deny-glob file to be kept and scanned instead of deleted:

```yaml
allow_suffixes: [".example", ".sample", ".template", ".dist"]
```

Example: `config.yaml` → DELETE, but `config.yaml.example` → SCAN.

### binary_deny_extensions / binary_allow_extensions

Extensions **without a dot**. Applied to files classified as binary:

```yaml
binary_deny_extensions:
  - exe
  - dll
  - so
  - jar
  - zip
  - gz
  - tar
  - rar
  - 7z
  - pdf
  - db
  - sqlite

binary_allow_extensions:
  - png
  - jpg
  - jpeg
  - gif
  - svg
  - ico
```

### NER settings

Two backends are supported for named-entity recognition.

#### HuggingFace backend (default)

Uses BERT-based transformers via `transformers` + `torch`. Faster on GPU, but requires heavy dependencies.

```yaml
ner:
  backend: hf   # or omit — hf is the default

  # Model from HuggingFace Hub or local path
  model: Davlan/bert-base-multilingual-cased-ner-hrl

  # Minimum confidence score (0.0 – 1.0)
  min_score: 0.7

  # Entity types to detect
  entity_types: [PER, ORG]

  # Device for inference
  # cpu    — CPU only (default)
  # cuda   — first available NVIDIA GPU
  # cuda:0 — specific GPU by index
  # auto   — Accelerate distributes automatically (pip install accelerate)
  device: cpu
```

CLI `--ner-device` overrides `device` from `policies.yaml`. If CUDA is requested but unavailable, a warning is logged and CPU is used.

#### GLiNER backend (recommended)

[GLiNER](https://github.com/urchade/GLiNER) — zero-shot NER architecture. Comparable speed, significantly fewer false positives. Does not require `torch`.

```bash
pip install gliner
```

```yaml
ner:
  backend: gliner
  model: urchade/gliner_multi-v2.1   # multilingual, ~186M params
  # model: urchade/gliner_large-v2.1 # larger, higher recall
  min_score: 0.5
  entity_types: [PER, ORG]
  # device: ignored for gliner backend
```

GLiNER uses descriptive labels: `PER` → `"person name"`, `ORG` → `"organization name"`. The mapping is handled automatically.

For offline environments, download the model in advance and specify the local path:

```yaml
ner:
  backend: hf
  model: /opt/models/bert-multilingual-ner
  min_score: 0.8
  device: cuda
```

---

## extractors.yaml — full schema

### Adding a language

Install the grammar package and add an entry:

```bash
uv add tree-sitter-go
```

```yaml
treesitter:
  languages:
    - id: go
      grammar_package: tree-sitter-go
      file_extensions: [.go]
      extract_zones: [comment_line, comment_block, string_literal]
```

Verify installation:

```bash
repo-sanitizer install-grammars --rulepack ./my-rules
```

If the package is not installed, the pipeline continues with `FallbackExtractor` for that language's files, but logs a warning.

### Special case: tree-sitter-typescript

This package exports `language_typescript()` and `language_tsx()` instead of the standard `language()`. Use separate IDs:

```yaml
- id: typescript
  grammar_package: tree-sitter-typescript
  file_extensions: [.ts]
  extract_zones: [comment_line, comment_block, string_literal]

- id: tsx
  grammar_package: tree-sitter-typescript
  file_extensions: [.tsx]
  extract_zones: [comment_line, comment_block, string_literal, template_literal]
```

### extract_zones values

| Value | What it captures |
|---|---|
| `comment_line` | `// ...` and `# ...` (single-line comments) |
| `comment_block` | `/* ... */` (block comments) |
| `docstring` | Python docstrings (`"""..."""` as first statement) |
| `string_literal` | String literals (`"..."`, `'...'`) |
| `template_literal` | JS/TS template literals (`` `...` ``) |

### zone_policy

```yaml
zone_policy:
  # Include string literals in redactable zones
  # false → only comments and docstrings
  redact_string_literals: true

  # Minimum string length to include in a zone
  min_string_length: 4
```

### on_parse_error

| Value | Behavior on parse failure |
|---|---|
| `fallback` | Use FallbackExtractor (regex comments) |
| `skip` | Do not scan the file at all |
| `fail` | Raise an exception and stop the pipeline |

### fallback_extractor

```yaml
fallback_extractor:
  enabled: true
  comment_patterns:
    - pattern: '#.*$'      # Python, Ruby, Shell
    - pattern: '//.*$'     # C, Java, JS, Go
    - pattern: '--.*$'     # Lua, SQL
    - pattern: ';.*$'      # Assembly, INI
```

Patterns are Python regex with `re.MULTILINE`. Each match becomes a zone.

---

## regex/pii_patterns.yaml — full schema

```yaml
patterns:
  - name: email                     # unique pattern name
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    category: PII                   # PII | SECRET | ENDPOINT | DICTIONARY
    severity: HIGH                  # CRITICAL | HIGH | MEDIUM | LOW | INFO

  - name: slack_token
    pattern: 'xox[baprs]-[0-9A-Za-z-]+'
    category: SECRET
    severity: CRITICAL

  - name: jira_ticket
    pattern: '[A-Z]{2,10}-\d{1,6}'
    category: DICTIONARY
    severity: MEDIUM

  - name: internal_url
    pattern: 'https?://[a-z0-9.-]*\.corp\.[a-z]+'
    category: ENDPOINT
    severity: MEDIUM
```

Patterns are applied:
- During working tree scanning (steps 3, 5) — to zone bytes for code files, to entire content for docs/config files.
- During history blob scanning (steps 6b, 8b) — to entire blob content.
- During history rewrite (step 7) — in the `blob_callback` as byte-level regex; matches are replaced with `[name:{hash12}]`.

**Note:** patterns are compiled as `re.compile(pattern)` — no flags by default. Add `(?i)` for case-insensitive matching.

---

## Dictionary files (dict/*.txt)

One term per line. Lines starting with `#` are comments.

```
# domains.txt
corp.internal
mycompany.io
staging.mycompany.io
```

```
# codenames.txt
# Project codenames
ProjectPhoenix
OperationAlpha
InitiativeZero
```

```
# clients.txt
Client A Corp
SomeEnterprise Ltd
```

Search uses Aho-Corasick (case-insensitive) — O(text length) regardless of dictionary size.

Domains in `dict/domains.txt` are also used by `EndpointDetector` during scanning.

---

## Configuration priority

```
CLI --max-file-mb 50
    ↓ if not set
env REPO_SANITIZER_MAX_FILE_MB=30
    ↓ if not set
rulepack/policies.yaml: max_file_mb: 20
    ↓ if not set
default: 20
```

---

## Version control for rulepacks

Store the rulepack in a separate Git repository:

```
company-sanitizer-rules/
├── VERSION          # bump when rules change
├── CHANGELOG.md     # what changed and why
├── policies.yaml
├── extractors.yaml
├── dict/
│   ├── domains.txt
│   └── clients.txt
└── regex/
    └── pii_patterns.yaml
```

Bump `VERSION` whenever dictionaries or patterns change. The version is logged in artifacts, making it easy to trace which rulepack produced a given bundle.
