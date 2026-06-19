"""Build-safety helpers for redaction.

The cardinal failure mode found auditing delivered batches: a redaction placeholder
spliced into a position that demanded specific syntax breaks the build (an unquoted
YAML scalar, a JSON string, a connection-string format template, an IP-literal field,
a code identifier). This module holds the small, pure, importable primitives that keep
replacements *syntactically inert in their landing context*:

  * ``is_template`` — a URL / connection-string / secret value that is actually a
    printf/interpolation TEMPLATE (``amqp://%s:%s@%s/%s``, ``?token={{$x}}``,
    ``${DB_URL}``), which must be left untouched (masking it orphans the args).
  * ``doc_ipv4`` / ``doc_ipv6`` — replace a public IP with a *valid* documentation-range
    literal instead of a ``[ipv4:hash]`` bracket marker, so YAML/compose/nginx still parse.
  * ``parse_status`` — parse-validity of every structured config in a tree, so the gate
    can flag a file that redaction turned from valid → invalid (the build-smoke gate).

Imports nothing from the package, so it is safe to use inside the git-filter-repo
subprocess (where the Scrubber lives) as well as in the gate.
"""

from __future__ import annotations

import hmac
import json
import math
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

try:  # PyYAML is a runtime dep; guard so a stripped env degrades to "can't check"
    import yaml
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore

try:  # tomllib is stdlib on 3.11+
    import tomllib
except Exception:  # noqa: BLE001
    tomllib = None  # type: ignore


def _hash(salt: bytes, value: bytes, length: int = 12) -> str:
    return hmac.new(salt, value, "sha256").hexdigest()[:length]


# ──────────────────────────────────────────────────────────────────────────────
# Format-string / interpolation template detection
# ──────────────────────────────────────────────────────────────────────────────
# A connection string / URL / secret value carrying a printf verb or an
# interpolation placeholder is a CODE TEMPLATE, not a real endpoint or credential:
#   fmt.Sprintf("amqp://%s:%s@%s:%s/%s", …)   <- the host is a runtime arg
#   "jdbc:postgresql://{host}:{port}/{db}"     <- str.format placeholders
#   "{{config('app.url')}}/reset?token={{$t}}" <- blade/mustache interpolation
#   "postgres://${USER}:${PASS}@${HOST}/db"    <- env interpolation
# Masking these splices a placeholder into the template, orphaning the printf args
# / breaking the interpolation → the build or runtime dial fails. So we LEAVE them
# untouched (they carry no real host/credential anyway — those arrive at runtime).
_TEMPLATE_RE = re.compile(
    r"""(?x)
      %[#0\-\ +']?[0-9.*]*[a-zA-Z@]   # printf / Go / ObjC verb:  %s %d %v %@ %02d %#v
    | \{\{.*?\}\}                      # mustache / blade / jinja  {{ x }}
    | \$\{[^}]*\}                      # shell / JS / gradle       ${VAR}
    | \#\{[^}]*\}                      # ruby / kotlin / scala     #{x}
    | \{[A-Za-z0-9_.]+\}               # str.format / C# / slf4j   {name} {0}
    | <[A-Za-z0-9_./%:\-]+>            # angle placeholder         <host>
    """
)


def is_template(value: str) -> bool:
    """True if ``value`` contains a printf verb or an interpolation placeholder
    (so it is a code template that must not be masked)."""
    return bool(_TEMPLATE_RE.search(value))


# ──────────────────────────────────────────────────────────────────────────────
# Our own placeholder shapes (so detectors treat an already-masked value as clean)
# ──────────────────────────────────────────────────────────────────────────────
# The structure-preserving masks (REDACTED_<hash> inside apiKey="…", a
# <hash>.example.invalid host inside postgres://…) intentionally keep enough
# syntax that the SAME regex-PII pattern would otherwise re-match the masked value
# (generic_api_key on REDACTED_<hash>, db_connection_* on the masked host),
# spinning the convergence loop and failing the gate forever. The detector must
# recognise our placeholders as already sanitised — the analogue of the gitleaks
# mask-allowlist. These shapes match replacements.py + history_ops.py exactly and
# are distinctive enough that a REAL secret/endpoint never contains one.
_MASK_TOKEN_RE = re.compile(
    r"REDACTED_(?:[A-Z0-9_]+_)?[0-9a-fA-F]{12}"
    r"|REDACTED_(?:EMAIL_|IP_|JWT_|URL_)?[0-9a-fA-F]{12}"
    r"|ANON_(?:PER|ORG)_[0-9a-fA-F]{12}"
    r"|TERM_[0-9a-fA-F]{12}"
    r"|Author_[0-9a-fA-F]{12}"
    r"|(?:user|author)_[0-9a-fA-F]{12}@example\.invalid"
    r"|[0-9a-fA-F]{8}\.example\.invalid"
)


def contains_mask(value: str) -> bool:
    """True if ``value`` already contains one of our redaction placeholders.

    Used to make the regex-PII detectors idempotent: a structure-preserving mask
    (``postgres://<hash>.example.invalid``, ``apiKey="REDACTED_<hash>"``) keeps the
    pattern shape, so without this guard the same pattern re-fires on the masked
    value and the gate never reaches zero."""
    return ".example.invalid" in value or bool(_MASK_TOKEN_RE.search(value))


# ──────────────────────────────────────────────────────────────────────────────
# Literal-replace safety (so a secret/person EXACT-replace never clobbers code)
# ──────────────────────────────────────────────────────────────────────────────
# A gitleaks/NER hit is exact-byte-replaced tree-wide. Without a guard this stamps
# REDACTED_<hash> / ANON_PER_<hash> over things that are NOT credentials/people but
# are load-bearing for the build: a dotted assembly version (4.0.0.0), a public
# domain / package / module name (lodash, google.com), a file/dir basename used in
# import paths, or a low-entropy plain identifier / dictionary word (Dashboard,
# Queue, blockchain). Dropping such a literal is SAFE: a value we wrongly skip that
# really is a secret is re-caught by the fail-closed post-rewrite gitleaks gate, so
# this can never cause a SILENT leak — at worst it surfaces on the Pass-2 worklist.

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DOTTED_VERSION_RE = re.compile(r"\d+(\.\d+){1,3}")
_BARE_DOMAIN_RE = re.compile(
    r"(?=.{4,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def is_identifier(value: str) -> bool:
    """A bare code identifier — masking it inside a LARGER identifier (substring)
    would corrupt code, so its literal replace must be word-boundaried."""
    return bool(_IDENT_RE.fullmatch(value))


def is_dotted_version(value: str) -> bool:
    return bool(_DOTTED_VERSION_RE.fullmatch(value))


# A 4-part dotted version (4.0.0.0, 1.2.3.4) is a VALID public IPv4 — masking it as
# an IP rewrites an assembly/package version and breaks .NET/Unity reference
# resolution. Skip a dotted quad whose CURRENT FIELD is a version context.
_VERSION_CTX_RE = re.compile(
    r"(?i)(version|assembly|<reference|packagereference|packageref|targetframework"
    r"|runtimeversion|frameworkversion|\bver\b|v\s*=|mscorlib|netstandard|netcoreapp)"
)
# Delimiters that END a value/field — the version keyword must be in the SAME field
# as the quad (so a `Version="x")] ... bind <IP>` does not falsely protect the IP).
_FIELD_CLOSE_RE = re.compile(r"[)\]};>,\n]")


def in_version_context(text: str, start: int, window: int = 48) -> bool:
    """True if the dotted quad at ``start`` sits in a version FIELD (so it is a
    version literal, not a deployment IP). Looks back ``window`` chars but only
    within the current field — the lookback is cut at the last field-closing
    delimiter, so a version keyword from a PREVIOUS field can't protect a later IP."""
    pre = text[max(0, start - window):start]
    cut = max((m.end() for m in _FIELD_CLOSE_RE.finditer(pre)), default=0)
    return bool(_VERSION_CTX_RE.search(pre[cut:]))


def is_bare_domain(value: str) -> bool:
    """A hostname / package-with-dots (foo.com, cloud.google.com) — not a secret."""
    return ("." in value and not value.replace(".", "").isdigit()
            and bool(_BARE_DOMAIN_RE.fullmatch(value)))


def looks_low_value_identifier(value: str) -> bool:
    """A plain identifier / dictionary word that is almost never a real secret —
    short, or low-entropy (lodash, Dashboard, blockchain, acme3, Queue, com).
    Applied to SECRET literals only (a short real surname must not be dropped from
    PERSON literals)."""
    if not is_identifier(value):
        return False
    return len(value) < 6 or shannon_entropy(value) < 3.2


def luhn_ok(value: str) -> bool:
    """Luhn checksum over the digits of ``value`` — distinguishes a real card number
    from a 16-digit float/fileID/model-weight run in numeric data (Unity prefabs,
    CatBoost models, FBX/SVG coords) that the credit_card regex otherwise mangles."""
    ds = [int(c) for c in value if c.isdigit()]
    if len(ds) < 12:
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ──────────────────────────────────────────────────────────────────────────────
# Value-kind-preserving placeholders (a redacted IP stays a VALID IP literal)
# ──────────────────────────────────────────────────────────────────────────────


def doc_ipv4(salt: bytes, raw: bytes) -> bytes:
    """A deterministic RFC5737 TEST-NET-3 literal (``203.0.113.1``–``.254``).

    A VALID IPv4 that keeps YAML / docker-compose port-specs / nginx / JSON
    parseable where a ``[ipv4:hash]`` bracket marker breaks them, stays
    recognisably a redacted address, and is itself non-global so a re-scan never
    re-flags it (avoiding a convergence loop)."""
    n = int(_hash(salt, raw, 6), 16) % 254 + 1
    return f"203.0.113.{n}".encode()


def doc_ipv6(salt: bytes, raw: bytes) -> bytes:
    """A deterministic RFC3849 documentation literal (``2001:db8::/32``)."""
    return f"2001:db8::{_hash(salt, raw, 4)}".encode()


# ──────────────────────────────────────────────────────────────────────────────
# Structured-config parse-validity (the PARSEABLE_CONFIGS build-smoke gate)
# ──────────────────────────────────────────────────────────────────────────────

# JSONC (comments / trailing commas) — json.loads would false-fail these.
_JSONC_NAMES = {"tsconfig.json", "jsconfig.json"}

# XML-family build/project descriptors.
_XML_EXTS = {
    ".xml", ".csproj", ".vbproj", ".fsproj", ".props", ".targets", ".nuspec",
    ".plist", ".resx", ".wsdl", ".xsd", ".xaml", ".storyboard", ".xib",
    ".pom", ".svg",
}
_XML_NAMES = {"pom.xml"}

# Directories that are vendored / generated — never our regression to worry about,
# and walking them is wasteful.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "bower_components", ".gradle", "Pods",
    "Carthage", "dist", "build", ".next", ".nuxt", ".venv", "__pycache__",
    "DerivedData", ".terraform", "target",
}


def _kind(path: Path) -> str | None:
    """Which strict parser applies to ``path`` (or None to skip)."""
    name = path.name.lower()
    suf = path.suffix.lower()
    if suf == ".json":
        if name in _JSONC_NAMES or name.endswith(".jsonc"):
            return None
        return "json"
    if suf in (".yml", ".yaml"):
        return "yaml"
    if suf == ".toml":
        return "toml"
    if suf in _XML_EXTS or name in _XML_NAMES:
        return "xml"
    return None


def _parse_ok(path: Path, kind: str) -> bool:
    """Best-effort parse. A read/decode failure returns True (not a redaction
    regression — we only care about valid→invalid transitions). A parser absent
    from the environment also returns True (cannot judge → do not block)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return True
    if not raw.strip():
        return True
    for enc in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            text = None
    if text is None:
        return True
    text = text.lstrip("﻿")
    try:
        if kind == "json":
            json.loads(text)
        elif kind == "yaml":
            if yaml is None:
                return True
            list(yaml.safe_load_all(text))
        elif kind == "toml":
            if tomllib is None:
                return True
            tomllib.loads(text)
        elif kind == "xml":
            ET.fromstring(text)
        return True
    except Exception:  # noqa: BLE001 — any parser error == "does not parse"
        return False


def parse_status(work_dir) -> dict[str, bool]:
    """Map ``relpath → parses?`` for every structured config kind under ``work_dir``.

    Used by the build-smoke gate: snapshot before redaction, re-check after, and a
    path that was True and is now False is a redaction-induced build break.
    """
    root = Path(work_dir)
    out: dict[str, bool] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            kind = _kind(p)
            if kind is None:
                continue
            out[os.path.relpath(p, root)] = _parse_ok(p, kind)
    return out


def config_parse_regressions(pre: dict[str, bool], post: dict[str, bool]) -> list[str]:
    """Paths that parsed before redaction and do NOT parse after (build breaks).

    Only valid→invalid transitions count: a file that was already broken, or that
    was intentionally deleted (absent from ``post``), is not a regression.
    """
    return sorted(
        path for path, ok_pre in pre.items()
        if ok_pre and post.get(path) is False
    )
