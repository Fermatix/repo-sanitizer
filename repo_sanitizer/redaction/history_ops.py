"""Pure byte/str scrubbing primitives for the git-history rewrite.

The git-filter-repo callbacks need to run in a separate subprocess (where
``git_filter_repo`` is imported). To keep that logic testable WITHOUT
git-filter-repo installed, the actual transformation lives here as a plain,
importable :class:`Scrubber` plus a few free functions; the generated filter
script (see ``steps/history_rewrite.py``) is a thin wrapper that imports this
module, builds a ``Scrubber`` from repr-injected rulepack data + the salt, and
wires its methods as the filter-repo callbacks.

Two distinct replacement modes:
  * **NON-brand** scrubbing (emails / phones / all rulepack PII patterns /
    gitleaks secret literals) — applied in Pass-1 ``sanitize``. Deterministic,
    salted, idempotent (email mask uses ``@example.invalid`` which the rulepack
    email pattern's ``(?!invalid\\b)`` lookahead refuses to re-match).
  * **brand** scrubbing — applied ONLY in Pass-3 ``apply-map`` from a tiered
    brand map produced by Pass-2 (Claude + codex). Pass-1 leaves brands in place
    (detection-only) so the brand gates stay RED as the Pass-2 worklist.
"""

from __future__ import annotations

import csv
import hmac
import io
import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable, Optional, Union


def hash12(salt: bytes, value: bytes, length: int = 12) -> str:
    """HMAC-SHA256 of ``value`` under ``salt``, hex-truncated (matches replacements.py)."""
    return hmac.new(salt, value, "sha256").hexdigest()[:length]


# ──────────────────────────────────────────────────────────────────────────────
# Brand map (the Pass-2 → Pass-3 contract)
# ──────────────────────────────────────────────────────────────────────────────
#
# A brand map is a list of rows; each row:
#   pattern        : str   — the matcher (a regex when is_regex, else a literal)
#   replacement    : str   — what to substitute (always treated as a LITERAL,
#                            never a regex template, so backslashes/`\1`/`&` are safe)
#   is_regex       : bool  — default True. Pass-2 compiles its tiers
#                            (substring / word-boundary / CamelCase-only /
#                            context-anchored / case-preserving) into the regex
#                            string here; this module just compiles + applies it.
#   preserve_case  : bool  — default False. When True the replacement adopts the
#                            matched text's case (UPPER / lower / Title).


def load_brand_map(path: Union[str, Path]) -> list[dict]:
    """Load a brand map from JSON (list, or ``{"rules": [...]}``) or CSV.

    CSV header must include ``pattern`` and ``replacement`` (``is_regex`` /
    ``preserve_case`` optional). Rows missing a pattern are skipped.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    raw_rows: list[dict]
    if p.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("rules", data.get("map", []))
        if not isinstance(data, list):
            raise ValueError(f"Brand map JSON must be a list (or {{'rules': [...]}}): {p}")
        raw_rows = [r for r in data if isinstance(r, dict)]
    else:
        reader = csv.DictReader(io.StringIO(text))
        raw_rows = list(reader)

    rows: list[dict] = []
    for r in raw_rows:
        pattern = (r.get("pattern") or "").strip() if isinstance(r.get("pattern"), str) else r.get("pattern")
        if not pattern:
            continue
        rows.append(
            {
                "pattern": pattern,
                "replacement": r.get("replacement", "") or "",
                "is_regex": _as_bool(r.get("is_regex"), default=True),
                "preserve_case": _as_bool(r.get("preserve_case"), default=False),
            }
        )
    # Validate every row compiles NOW so a bad Pass-2 pattern fails loudly here,
    # before any history is touched (compile_brand_map raises on a bad regex).
    compile_brand_map(rows)
    return rows


def _as_bool(value: object, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def compile_brand_map(rows: list[dict]) -> list[tuple[re.Pattern, str, bool]]:
    """Compile brand rows → ``[(compiled, replacement, preserve_case)]``.

    Sorted by pattern length DESC so a longer brand (``extyl``) is masked before
    a shorter prefix (``ext``) — sequential ``re.sub`` passes, so order matters.
    Literal (``is_regex=False``) patterns get ``re.escape`` + ``IGNORECASE``;
    regex patterns are compiled verbatim (Pass-2 embeds its own ``(?i)`` / ``\\b``).
    A row that fails to compile RAISES ``ValueError`` — silently skipping it would
    let a mapped brand survive in all history while apply-map exits 0.
    """
    compiled: list[tuple[re.Pattern, str, bool]] = []
    for row in sorted(rows, key=lambda r: len(r.get("pattern", "")), reverse=True):
        pattern = row.get("pattern", "")
        if not pattern:
            continue
        try:
            if row.get("is_regex", True):
                rx = re.compile(pattern)
            else:
                rx = re.compile(re.escape(pattern), re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid brand-map regex {pattern!r}: {e}") from e
        compiled.append((rx, row.get("replacement", ""), bool(row.get("preserve_case", False))))
    return compiled


def _match_case(matched: str, replacement: str) -> str:
    """Return ``replacement`` recased to mirror ``matched`` (UPPER/lower/Title)."""
    if not matched or not replacement:
        return replacement
    if matched.isupper():
        return replacement.upper()
    if matched.islower():
        return replacement.lower()
    if matched[:1].isupper() and matched[1:].islower():
        return replacement[:1].upper() + replacement[1:].lower()
    return replacement


def apply_brand_map(text: str, compiled: list[tuple[re.Pattern, str, bool]]) -> str:
    """Apply a compiled brand map to a unicode string."""
    for rx, replacement, preserve in compiled:
        if preserve:
            text = rx.sub(lambda m: _match_case(m.group(0), replacement), text)
        else:
            # function form → replacement is a LITERAL (no regex backref expansion)
            text = rx.sub(lambda m: replacement, text)
    return text


def apply_brand_map_bytes(data: bytes, compiled: list[tuple[re.Pattern, str, bool]]) -> bytes:
    """Apply a compiled brand map to bytes, trying utf-8 then cp1251.

    Brand matching is done on decoded text so ``re.IGNORECASE`` folds Cyrillic
    (Я↔я), which byte-regex IGNORECASE does not. cp1251 is the documented Bitrix
    PHP encoding — without this fallback a brand in a cp1251 blob/path would be
    DETECTED by the (encoding-aware) scan but left in place by the rewrite.
    Genuinely binary blobs fail both decodes (cp1251 rejects undefined bytes like
    0x98) and are returned unchanged; ASCII placeholder replacements re-encode
    cleanly and untouched text round-trips its original encoding.
    """
    if not compiled:
        return data
    for enc in ("utf-8", "cp1251"):
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        return apply_brand_map(text, compiled).encode(enc, errors="replace")
    return data


# ──────────────────────────────────────────────────────────────────────────────
# Scrubber — the filter-repo callback bundle
# ──────────────────────────────────────────────────────────────────────────────

_PHONE_NAMES = ("phone_e164", "phone_ru", "phone")
_PHONE_MASK = b"+0000000000"


def _literal_repl(salt: bytes, values, prefix: str) -> list[tuple[bytes, bytes]]:
    """Build (raw_bytes, mask) replacements for exact-literal scrubbing.

    Each value is matched in BOTH utf-8 AND cp1251 byte forms (a Cyrillic name /
    secret in a cp1251 Bitrix blob would not match a utf-8-only literal), with a
    single stable mask ``<prefix><hash(utf-8 value)>`` for every form. Longest
    value first so a longer value containing a shorter one is masked first.
    """
    out: list[tuple[bytes, bytes]] = []
    for v in sorted({s for s in (values or []) if s}, key=len, reverse=True):
        mask = (prefix + hash12(salt, v.encode("utf-8"))).encode()
        forms: set[bytes] = set()
        for enc in ("utf-8", "cp1251"):
            try:
                forms.add(v.encode(enc))
            except UnicodeEncodeError:
                pass
        for raw in forms:
            out.append((raw, mask))
    return out


class Scrubber:
    """Holds compiled scrubbing state and exposes git-filter-repo callbacks.

    Construct once per rewrite (the generated script does this with repr-injected
    rulepack data and the salt), then pass the bound methods as callbacks.
    """

    def __init__(
        self,
        salt: bytes,
        *,
        pii_pattern_defs: Optional[list] = None,
        secret_literals: Optional[list] = None,
        person_literals: Optional[list] = None,
        brand_map_rows: Optional[list] = None,
        deny_globs: Optional[list] = None,
        binary_deny_extensions: Optional[list] = None,
        allow_suffixes: Optional[list] = None,
        rewrite_authors: bool = True,
    ) -> None:
        self.salt = salt
        self.rewrite_authors = rewrite_authors

        # PII patterns compiled as BYTE regexes (applied to raw blob bytes).
        self._email_re: Optional[re.Pattern] = None
        self._phone_res: list[re.Pattern] = []
        self._other_pii: list[tuple[bytes, re.Pattern]] = []
        for name, pattern in (pii_pattern_defs or []):
            try:
                rx = re.compile(pattern.encode(), re.MULTILINE)
            except re.error:
                continue
            if name == "email":
                self._email_re = rx
            elif name in _PHONE_NAMES:
                self._phone_res.append(rx)
            else:
                self._other_pii.append((name.encode(), rx))

        # Secret literals → REDACTED_<hash>, exact byte replace (utf-8 + cp1251).
        self._secret_repl = _literal_repl(salt, secret_literals, "REDACTED_")
        # NER person names → ANON_PER_<hash> (matches replacements.mask_person).
        # Closes the leak where filter-repo resets the working tree from
        # blob_callback output (no NER) and a working-tree-redacted name would
        # reappear in the shipped HEAD.
        self._person_repl = _literal_repl(salt, person_literals, "ANON_PER_")

        self._brands = compile_brand_map(brand_map_rows or [])
        self._deny_globs = list(deny_globs or [])
        self._binary_deny = {e.lower().lstrip(".") for e in (binary_deny_extensions or [])}
        self._allow_suffixes = tuple(allow_suffixes or [])

    # ── author identity ──────────────────────────────────────────────────────

    def author_name(self, name: bytes) -> bytes:
        return b"Author_" + hash12(self.salt, name).encode()

    def author_email(self, email: bytes) -> bytes:
        return b"author_" + hash12(self.salt, email).encode() + b"@example.invalid"

    # ── content scrubbing ──────────────────────────────────────────────────────

    def _scrub_nonbrand(self, data: bytes) -> bytes:
        """gitleaks secret literals → REDACTED_<hash>, NER person names →
        ANON_PER_<hash>, email → user_<hash>@example.invalid, phone → +0…, all
        other PII → [name:hash]. (No brands.)

        Secret/person literals are applied FIRST (whole-value, exact bytes) so a
        secret which happens to contain an email/IP substring is masked entirely
        — otherwise the PII pass would rewrite the substring first and the
        exact-bytes secret replace would then miss the mangled remainder."""
        for raw, repl in self._secret_repl:
            if raw in data:
                data = data.replace(raw, repl)
        for raw, repl in self._person_repl:
            if raw in data:
                data = data.replace(raw, repl)
        if self._email_re is not None:
            data = self._email_re.sub(
                lambda m: b"user_" + hash12(self.salt, m.group()).encode() + b"@example.invalid",
                data,
            )
        for rx in self._phone_res:
            data = rx.sub(_PHONE_MASK, data)
        for name, rx in self._other_pii:
            data = rx.sub(
                lambda m, _n=name: b"[" + _n + b":" + hash12(self.salt, m.group()[:64]).encode() + b"]",
                data,
            )
        return data

    def message(self, message: bytes) -> bytes:
        """Commit-message callback: full non-brand scrub + brand map."""
        out = self._scrub_nonbrand(message)
        out = apply_brand_map_bytes(out, self._brands)
        return out

    def blob(self, blob, callback_data=None) -> None:
        """Blob callback: skip binary, else non-brand scrub + brand map in place."""
        try:
            data = blob.data
            if b"\x00" in data[:8192]:
                return
            out = self._scrub_nonbrand(data)
            out = apply_brand_map_bytes(out, self._brands)
            blob.data = out
        except Exception:
            pass

    # ── path handling ──────────────────────────────────────────────────────────

    def should_remove_path(self, path: bytes) -> bool:
        path_str = path.decode("utf-8", errors="replace")
        # Allow-suffixed files (config.yaml.example, .env.template, …) are KEPT
        # and scanned by inventory — history must agree, or a file present in the
        # delivered working tree would be missing from every old commit.
        if any(path_str.endswith(s) for s in self._allow_suffixes):
            return False
        name = path_str.split("/")[-1]
        for g in self._deny_globs:
            if fnmatch(name, g.split("/")[-1]):
                return True
        ext = path_str.rsplit(".", 1)[-1].lower() if "." in path_str else ""
        return ext in self._binary_deny

    def filename(self, path: bytes) -> bytes:
        """Filename callback: delete deny/binary paths, else rename brand segments
        (same brand map as content → ``package == dir`` stays coherent)."""
        if self.should_remove_path(path):
            return b""
        return apply_brand_map_bytes(path, self._brands)
