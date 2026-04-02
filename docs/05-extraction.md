# 5. Zone Extraction

This document describes the zone extraction subsystem that enables context-aware, syntax-sensitive scanning for code files. For how zones are used by detectors, see [§4.1](04-detection.md#41-detector-interface). For how zone extraction integrates into the pipeline, see [§3.4](03-pipeline.md#34-step-3--pre-scan-working-tree).

---

## 5.1 Motivation for Zone-Based Scanning

Source code files contain two fundamentally different categories of text:

1. **Structural elements** — identifiers (variable names, function names, class names, import paths, type annotations). These are part of the program's interface and should not be modified; they rarely contain human-readable sensitive data.

2. **Human-readable content** — string literals, comments, and docstrings. These are written for human consumption and are the locations where developers are most likely to embed sensitive values (credentials, personal data, internal URLs, TODO comments with ticket numbers, debug strings, etc.).

Scanning the full content of a source file without zone restriction produces a high rate of false positives on structural elements. For example, a variable named `user_email_field` would match an email pattern detector incorrectly. Zone-based scanning restricts detection (and redaction) to only those byte intervals that contain human-readable content.

**Zone semantics:** A `Zone` is a closed-open byte interval `[start, end)` within the decoded UTF-8 string content of a file. Detectors may only emit findings whose span falls entirely within at least one zone (see [§2.3](02-data-model.md#23-zone)).

---

## 5.2 TreeSitterExtractor

**Implementation:** `repo_sanitizer/extractors/treesitter.py`

`TreeSitterExtractor` parses source files using language-specific grammars and extracts zone intervals by traversing the resulting Abstract Syntax Tree (AST).

### 5.2.1 Grammar Resolution

For each language, the extractor resolves its tree-sitter grammar through a three-level fallback:

**Level 1 — Standalone package:**
```python
import importlib
mod = importlib.import_module(grammar_package)  # e.g., "tree_sitter_python"
fn_name = _GRAMMAR_FN_OVERRIDES.get(lang_id, "language")
lang = getattr(mod, fn_name)()
```

Non-standard function names are specified in `_GRAMMAR_FN_OVERRIDES`:

```python
_GRAMMAR_FN_OVERRIDES = {
    "typescript": "language_typescript",
    "tsx":        "language_tsx",
    # ... others with non-default function names
}
```

**Level 2 — tree-sitter-language-pack:**
```python
from tree_sitter_language_pack import get_language
lang_pack_id = _LANGUAGE_PACK_ID_OVERRIDES.get(lang_id, lang_id)
lang = get_language(lang_pack_id)
```

`_LANGUAGE_PACK_ID_OVERRIDES` maps language IDs that differ from the pack's naming convention.

**Level 3 — RuntimeError:**
If both attempts fail, a `RuntimeError` is raised. The caller (Step 3) catches this and either calls `FallbackExtractor` or skips the file, depending on the `on_parse_error` policy.

Parsers are cached per language ID after first successful resolution to avoid repeated module imports across files of the same language.

### 5.2.2 extract_zones() Return Semantics

```python
def extract_zones(file_path: str, content: str) -> list[Zone] | None:
```

| Return value | Meaning |
|---|---|
| `None` | File extension not recognized by this extractor — caller should try `FallbackExtractor` |
| `[]` (empty list) | File recognized as a supported language but contains no extractable zones |
| `[Zone(...), ...]` | List of zones to scan; detectors operate only within these intervals |

The `None` vs `[]` distinction is critical: `None` triggers fallback; `[]` means "scan nothing."

### 5.2.3 Zone Type Mapping

Zones are extracted from AST nodes whose type matches the configured `extract_zones` list for the language:

| Zone type string | Tree-sitter node types | Description |
|---|---|---|
| `comment_line` | `comment`, `line_comment` | Single-line comments (`#`, `//`, `--`) |
| `comment_block` | `block_comment`, `multiline_comment` | Block comments (`/* */`, `{- -}`) |
| `docstring` | Python: first string in scope | Python docstrings (not arbitrary strings) |
| `string_literal` | `string`, `string_literal`, `interpreted_string_literal` | String nodes of all kinds |
| `template_literal` | `template_string` | JS/TS template literals (backtick strings) |

The mapping from zone type string to concrete node type names is defined in `NODE_TYPE_MAP`, a dictionary with one entry per language (140+ entries). For example:

```python
NODE_TYPE_MAP = {
    "python": {
        "comment_line":   ["comment"],
        "docstring":      ["expression_statement"],  # first string stmt in scope
        "string_literal": ["string"],
    },
    "javascript": {
        "comment_line":    ["comment"],
        "comment_block":   ["block_comment"],
        "string_literal":  ["string", "template_string"],
        "template_literal":["template_string"],
    },
    # ... 140+ more languages
}
```

### 5.2.4 Zone Policy

Two policy flags from `extractors.yaml` govern string literal handling:

**`redact_string_literals: bool`** — If `False`, string literal nodes are not extracted even if `string_literal` is listed in `extract_zones`. This allows scanning comments without modifying string values (useful when string literals contain program data rather than human-readable text).

**`min_string_length: int`** — String literal zones shorter than this threshold (in bytes) are discarded. Short strings are typically single-character tokens, boolean literals, or format specifiers that are unlikely to contain sensitive data. Default: 4.

### 5.2.5 on_parse_error Policy

Configured in `extractors.yaml`:

| Value | Behavior when tree-sitter parse fails |
|---|---|
| `fallback` | Return `None`; caller invokes `FallbackExtractor` |
| `skip` | Return `[]`; file is not scanned |
| `fail` | Raise exception; file scan is aborted |

Default: `fallback`.

### 5.2.6 Python Docstring Handling

Python docstrings are a special case: a string literal is considered a docstring only if it appears as the first statement of a module, class, or function body. `TreeSitterExtractor` identifies these by checking that a `string` node is the first child of an `expression_statement` that is the first statement of a `block` node within a function/class/module definition.

This specificity prevents arbitrary string literals from being miscategorized as docstrings, and ensures that zone-policy settings for `docstring` and `string_literal` apply to the correct node types independently.

---

## 5.3 FallbackExtractor

**Implementation:** `repo_sanitizer/extractors/fallback.py`

`FallbackExtractor` is a lightweight alternative that uses regular expressions to locate comment-like regions. It is used when:

1. `TreeSitterExtractor` returns `None` (grammar unavailable).
2. `on_parse_error` is `fallback` and tree-sitter fails to parse the file.

### Algorithm

```python
import re

DEFAULT_PATTERNS = [
    re.compile(r"#.*$",  re.MULTILINE),
    re.compile(r"//.*$", re.MULTILINE),
    re.compile(r"--.*$", re.MULTILINE),
]

def extract_zones(self, file_path: str, content: str) -> list[Zone]:
    zones = []
    for pattern in self.patterns:
        for match in pattern.finditer(content):
            zones.append(Zone(start=match.start(), end=match.end()))
    return _merge_zones(sorted(zones, key=lambda z: z.start))
```

Adjacent or overlapping zones from different patterns are merged into a single `Zone`.

### Configurable Patterns

Additional patterns can be added via `extractors.yaml`:

```yaml
fallback_extractor:
  enabled: true
  comment_patterns:
    - "^\\s*#.*$"
    - "^\\s*;.*$"   # INI/assembly comments
```

The default patterns (`#`, `//`, `--`) cover Python/Ruby/Shell, C-family languages (JavaScript, Go, Java, Rust, C, C++), and Lua/SQL respectively.

---

## 5.4 Zone Policy Interaction with Redaction

Zone extraction serves two distinct purposes in the pipeline:

**At scan time (Step 3):** Detectors receive zones as part of the `ScanTarget` and filter findings accordingly. A finding that falls outside all zones is silently discarded.

**At redact time (Step 4):** For `CODE` category files, a second zone-membership check is performed before applying each replacement from `pre_findings`. This check is computed from a fresh zone extraction on the (possibly already partially modified) content.

This double check provides defense-in-depth: even if zone extraction between Steps 3 and 4 produces slightly different zones (due to content changes from earlier replacements in the same file), only findings confirmed to be within a zone at redact time are applied.

### Why zones=None for Blob Scans

Historical blob scans (Steps 6b and 8b) use `ScanTarget(zones=None)` for all blobs, meaning detectors scan the entire blob content. Reasons:

1. **Performance:** Running tree-sitter on potentially thousands of historical blobs would add significant latency without proportional benefit.
2. **No redaction at blob level:** Blob scan findings inform the history rewrite step (Step 7), which uses pattern-based callbacks rather than zone-aware offset replacement. The `blob_callback` in the generated filter script applies regex replacements to the entire blob text.
3. **False positive tolerance:** The blob scan is a secondary scan for historical coverage. Its higher false-positive rate (due to no zone filtering) is acceptable because the gate check (Step 9) evaluates all three scan scopes together.

---

## 5.5 Grammar Installation

The `install-grammars` CLI command checks and reports the grammar installation status for all languages configured in the rulepack:

```bash
repo-sanitizer install-grammars --rulepack examples/rules
```

**GrammarStatus dataclass:**

```python
@dataclass
class GrammarStatus:
    language_id:    str
    grammar_package:str
    installed:      bool
    missing_attr:   bool   # package installed but function not found
    via_language_pack: bool
```

The command first attempts to install `tree-sitter-language-pack` (covers 165+ languages in a single package), then identifies any remaining languages not covered and attempts to install their individual packages. Languages that cannot be installed are listed as warnings; the fallback extractor will handle their files.

At pipeline startup (Step 3), `_warn_missing_grammars()` logs a warning for each language in the rulepack whose grammar could not be loaded, allowing operators to identify which file types will be processed with reduced accuracy.

---

## 5.6 Language Coverage

### Via Individual Packages

The default `examples/rules/extractors.yaml` configures 140+ languages including:

**Systems and compiled languages:** C, C++, C#, CUDA, Objective-C, Rust, Go, Zig, Odin, V, Nim, D, Hare, Assembly, Fortran, Ada, COBOL, Pascal

**JVM languages:** Java, Kotlin, Scala, Groovy, Clojure

**Scripting languages:** Python, Ruby, PHP, Perl, Lua, Tcl, GDScript, Squirrel

**Web technologies:** JavaScript, TypeScript, TSX, JSX, HTML, CSS, SCSS, SASS, Less, Vue, Svelte, Astro

**Mobile:** Swift, Dart, Kotlin

**Functional languages:** Haskell, OCaml, F#, Elixir, Erlang, Elm, PureScript, Common Lisp, Scheme, Racket, Fennel, Janet, Emacs Lisp, Haxe, Gleam, Pony, Agda

**Shell and build systems:** Bash, Fish, PowerShell, CMake, Make, Meson, Ninja, Starlark (Bazel), Nix, Bitbake, GN, Puppet, Dockerfile

**Data and configuration languages:** YAML, TOML, JSON, JSONNET, INI, Properties format, RON, KDL

**Query and schema languages:** SQL, GraphQL, SPARQL, Protocol Buffers, Smithy, Thrift, Cap'n Proto

**Document formats:** XML, DTD, Markdown, LaTeX, reStructuredText, Org-mode, BibTeX, PO (gettext)

**Infrastructure and cloud:** HCL (Terraform), Bicep, Prisma, Rego (Open Policy Agent), Beancount

**Shader and hardware languages:** GLSL, HLSL, WGSL, Verilog, VHDL, LLVM IR

**Blockchain:** Solidity, Cairo (StarkNet), Clarity (Stacks), FunC (TON)

**Miscellaneous:** WebAssembly (WAT), PEM, Vim script, Smali, Typst, R, Julia, ActionScript, Arduino, BSL, Magik (GE), Apex (Salesforce)

### Via tree-sitter-language-pack

Installing the `tree-sitter-language-pack` Python package provides grammars for 165+ languages in a single installation, covering the above list plus additional languages. This is the recommended installation method.

### Non-Standard Grammar APIs

Some grammar packages expose functions with non-standard names. The `_GRAMMAR_FN_OVERRIDES` dictionary handles these cases:

| Language | Package | Standard function | Actual function |
|---|---|---|---|
| TypeScript | `tree-sitter-typescript` | `language()` | `language_typescript()` |
| TSX | `tree-sitter-typescript` | `language()` | `language_tsx()` |

For `tree-sitter-language-pack`, the `_LANGUAGE_PACK_ID_OVERRIDES` dictionary handles cases where the pack uses a different identifier than the language's `id` field in `extractors.yaml`.
