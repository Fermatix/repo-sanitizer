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
import ipaddress
import json
import logging
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable, Optional, Union

# Single source of truth for "which IP is worth redacting". endpoint imports only
# stdlib + the lightweight detectors.base, so this is safe to import inside the
# git-filter-repo subprocess (where Scrubber is instantiated).
from repo_sanitizer.buildsafe import (
    doc_ipv4,
    doc_ipv6,
    in_version_context,
    is_identifier,
    is_template,
    luhn_ok,
)
from repo_sanitizer.detectors.endpoint import (
    IPV4_PATTERN,
    IPV6_PATTERN,
    URL_HOST_PATTERN,
    _is_kept_url_host,
    _is_public_ip,
)

logger = logging.getLogger(__name__)

# ── Build-safe routing of PII/secret patterns (by rulepack NAME) ───────────────
# The whole-blob history scrub must never splice a syntactically-invalid token into
# code/config. Three patterns demand structure-preserving handling instead of the
# generic "[name:hash]" marker (which breaks YAML/compose/nginx/JSON and orphans
# format-string args):
#
#  * URL / connection-string patterns → mask only the HOST (keep scheme/port/path),
#    and SKIP format-string templates (amqp://%s:%s@…). Result stays a valid,
#    parseable connection string. (http(s) URLs are already host-masked by the
#    dedicated _scrub_url_hosts_bytes pass, so only the non-http schemes route here.)
_URL_ENDPOINT_NAMES = frozenset({
    "db_connection_postgresql", "db_connection_mysql", "db_connection_mongodb",
    "db_connection_redis", "db_connection_amqp", "jdbc_url",
    # http(s) credential / internal-TLD URLs: also host-masked (keep scheme so
    # nginx proxy_pass / YAML stay valid; userinfo credentials are dropped).
    "internal_corp_url", "basic_auth_in_url",
})
#  * Grouped secret patterns whose match wraps the secret VALUE in keyword + quotes
#    (apiKey = "VALUE", AWS_SECRET_ACCESS_KEY=VALUE) → replace ONLY the captured
#    value group, keeping the surrounding declaration intact (and skip templates).
_GROUPED_SECRET_NAMES = frozenset({"generic_api_key", "aws_secret_key"})
#  * credit_card → mask only if the digit run passes the Luhn checksum; a 16-digit
#    float / Unity fileID / model weight that merely looks card-shaped is left
#    intact (it is numeric DATA, masking it breaks the asset/model/JSON).
_LUHN_NAMES = frozenset({"credit_card"})
#  * secret_url_param ("?token=VALUE") → keep the "?name=" prefix, mask only the value.
#
# Everything else (jwt, aws_access_key_id, github/gitlab/slack/stripe tokens, ssn,
# credit_card, iban, passport_ru, inn_ru, …) is masked to an IDENTIFIER-SAFE token
# "REDACTED_<NAME>_<hash>" (letters/digits/underscore only — a valid bare YAML
# scalar / JSON-string content), never a "[name:hash]" bracket marker.

# scheme://[userinfo@]host[:port][/path…]. Group "scheme" keeps an optional
# subscheme prefix so jdbc:postgresql:// and postgres:// both reconstruct; the
# host runs up to the first :/?#, userinfo is dropped (credentials gone).
_SCHEME_AUTHORITY_RE = re.compile(
    rb"^(?P<scheme>(?:[A-Za-z][\w+.\-]*:)?[A-Za-z][\w+.\-]*://)"
    rb"(?:(?P<userinfo>[^/@\s]*)@)?"
    rb"(?P<host>\[[0-9A-Fa-f:.]+\]|[^/:\s?#]+)",
    re.IGNORECASE,
)


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


def detect_brand_map_collisions(rows: list[dict]) -> dict[str, list[str]]:
    """Group brand-map rows by their replacement; return only the replacements
    that ≥2 DISTINCT patterns map to (``{replacement: [pattern, ...]}``).

    A collision is the signal for the Pass-2 failure mode where distinct brands
    were collapsed onto one ``acmeN`` placeholder (dup identifiers / consts /
    ``<string name>`` / invalid ``acme1,`` JSON) — things ``json.loads`` cannot
    see. NOT necessarily a bug: a tiered map legitimately reuses one placeholder
    across its own tiers (substring + word-boundary forms of the SAME brand), so
    this is advisory (the caller logs a WARNING, never hard-fails)."""
    by_replacement: dict[str, set[str]] = {}
    for row in rows:
        replacement = (row.get("replacement") or "").strip()
        pattern = row.get("pattern") or ""
        if not replacement or not pattern:
            continue
        by_replacement.setdefault(replacement, set()).add(pattern)
    return {
        repl: sorted(pats)
        for repl, pats in by_replacement.items()
        if len(pats) >= 2
    }


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


def _literal_repl(salt: bytes, values, prefix: str) -> list[tuple[object, bytes]]:
    """Build (matcher, mask) replacements for literal scrubbing.

    Each value gets a single stable mask ``<prefix><hash(utf-8 value)>``. The
    matcher is:
      * a WORD-BOUNDARIED compiled byte-regex when the value is a bare ASCII
        identifier — so a standalone token is masked but a SUBSTRING of a larger
        identifier is NOT (a literal ``Queue`` must not clobber ``QueueDeclare``,
        ``com`` must not clobber ``components``); this was the dominant
        secret/person-literal build break;
      * else the raw bytes in BOTH utf-8 AND cp1251 forms (a Cyrillic name/secret
        in a cp1251 Bitrix blob would miss a utf-8-only literal), exact-replaced.
    Longest value first so a longer value containing a shorter one is masked first.
    """
    out: list[tuple[object, bytes]] = []
    for v in sorted({s for s in (values or []) if s}, key=len, reverse=True):
        mask = (prefix + hash12(salt, v.encode("utf-8"))).encode()
        if is_identifier(v):
            out.append((
                re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(v.encode()) + rb"(?![A-Za-z0-9_])"),
                mask,
            ))
            continue
        forms: set[bytes] = set()
        for enc in ("utf-8", "cp1251"):
            try:
                forms.add(v.encode(enc))
            except UnicodeEncodeError:
                pass
        for raw in forms:
            out.append((raw, mask))
    return out


def _apply_literal(data: bytes, matcher: object, repl: bytes) -> bytes:
    """Apply one (matcher, mask) from ``_literal_repl``: a compiled byte-regex
    (word-boundaried identifier) → ``sub``; raw bytes → exact ``replace``."""
    if isinstance(matcher, bytes):
        return data.replace(matcher, repl) if matcher in data else data
    return matcher.sub(lambda _m: repl, data)


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
        keep: Optional[list] = None,
        scrub_public_ips: bool = False,
        scrub_urls: bool = False,
    ) -> None:
        self.salt = salt
        self.rewrite_authors = rewrite_authors

        # Allowlisted IP/domain literals (lowercased), exempt from the IP/URL pass.
        self._keep = {k.lower() for k in (keep or [])}
        # Public-IP scrubbing replaces the removed regex `ipv4` rulepack pattern.
        # Enabled ONLY for the Pass-1 sanitize rewrite; the Pass-3 apply-map pass
        # stays brand-only. Byte regexes compiled from the (str) endpoint patterns
        # — pure-ASCII, so .encode() round-trips; \w is ASCII in byte mode.
        self._scrub_public_ips = bool(scrub_public_ips)
        if self._scrub_public_ips:
            self._ipv4_re = re.compile(IPV4_PATTERN.pattern.encode())
            self._ipv6_re = re.compile(IPV6_PATTERN.pattern.encode())
        # URL-host scrubbing: mask the host of any http(s) URL that is not
        # universal public infra (see endpoint._is_kept_url_host). Pass-1 only.
        self._scrub_urls = bool(scrub_urls)
        if self._scrub_urls:
            self._url_re = re.compile(URL_HOST_PATTERN.pattern.encode(), re.IGNORECASE)

        # PII/secret patterns compiled as BYTE regexes (applied to raw blob bytes),
        # routed by NAME so each produces a build-SAFE replacement (see the
        # _URL_ENDPOINT_NAMES / _GROUPED_SECRET_NAMES notes above).
        self._email_re: Optional[re.Pattern] = None
        self._phone_res: list[re.Pattern] = []
        self._url_endpoint_res: list[re.Pattern] = []           # host-mask, template-skip
        self._grouped_secret_res: list[re.Pattern] = []         # mask group(1) only
        self._secret_url_re: Optional[re.Pattern] = None        # keep "?name=", mask value
        self._luhn_res: list[tuple[bytes, re.Pattern]] = []     # mask only if Luhn-valid
        self._other_pii: list[tuple[bytes, re.Pattern]] = []    # REDACTED_<NAME>_<hash>
        for name, pattern in (pii_pattern_defs or []):
            try:
                rx = re.compile(pattern.encode(), re.MULTILINE)
            except re.error:
                continue
            if name == "email":
                self._email_re = rx
            elif name in _PHONE_NAMES:
                self._phone_res.append(rx)
            elif name in _URL_ENDPOINT_NAMES:
                self._url_endpoint_res.append(rx)
            elif name == "secret_url_param":
                self._secret_url_re = rx
            elif name in _GROUPED_SECRET_NAMES:
                self._grouped_secret_res.append(rx)
            elif name in _LUHN_NAMES:
                self._luhn_res.append((name.encode(), rx))
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
        ANON_PER_<hash>, email → user_<hash>@example.invalid, phone → +0…, and the
        remaining PII/secret patterns to BUILD-SAFE placeholders (no brands).

        Every replacement is syntactically inert in its landing context — the
        cardinal rule learnt auditing delivered batches (18/27 repos were
        build-broken by a placeholder spliced into syntax it didn't fit):
          * connection-string / URL endpoints → mask only the HOST (keep scheme/
            port/path), and SKIP format-string templates (amqp://%s:%s@…);
          * grouped secrets (apiKey="VALUE") → mask only the value group;
          * secret URL params (?token=VALUE) → keep "?name=", mask only the value;
          * public IPs → a valid documentation-range IP literal (not a bracket marker);
          * everything else → an identifier-safe REDACTED_<NAME>_<hash> token, never
            a "[name:hash]" marker (which breaks YAML/compose/nginx/JSON).

        Secret/person literals are applied FIRST (identifier values word-boundaried,
        everything else exact bytes) so a secret which happens to contain an email/IP
        substring is masked entirely."""
        for matcher, repl in self._secret_repl:
            data = _apply_literal(data, matcher, repl)
        for matcher, repl in self._person_repl:
            data = _apply_literal(data, matcher, repl)
        if self._email_re is not None:
            data = self._email_re.sub(
                lambda m: b"user_" + hash12(self.salt, m.group()).encode() + b"@example.invalid",
                data,
            )
        for rx in self._phone_res:
            data = rx.sub(_PHONE_MASK, data)
        # Connection-string / URL endpoints: host-only mask, template-skip.
        for rx in self._url_endpoint_res:
            data = rx.sub(self._mask_endpoint_url_match, data)
        # Grouped secrets (apiKey="VALUE"): mask the captured value group only.
        for rx in self._grouped_secret_res:
            data = rx.sub(self._mask_grouped, data)
        # Secret URL param (?token=VALUE): keep "?name=", mask the value only.
        if self._secret_url_re is not None:
            data = self._secret_url_re.sub(self._mask_url_param, data)
        # credit_card: mask only a Luhn-valid run (a card-shaped numeric-DATA run —
        # Unity fileID / model weight / FBX coord — is left intact so the asset
        # stays parseable/compilable).
        for name, rx in self._luhn_res:
            data = rx.sub(lambda m, _n=name: self._mask_if_luhn(m, _n), data)
        # Remaining PII/secret patterns → identifier-safe token (no "[…]" marker).
        for name, rx in self._other_pii:
            data = rx.sub(
                lambda m, _n=name: b"REDACTED_" + _n.upper() + b"_"
                + hash12(self.salt, m.group()[:64]).encode(),
                data,
            )
        if self._scrub_urls:
            data = self._scrub_url_hosts_bytes(data)
        if self._scrub_public_ips:
            data = self._scrub_public_ip_bytes(data)
        return data

    def _mask_endpoint_url_match(self, m: "re.Match[bytes]") -> bytes:
        return self._mask_endpoint_url(m.group())

    def _mask_endpoint_url(self, raw: bytes) -> bytes:
        """Mask a connection-string / URL's userinfo+host while KEEPING the scheme,
        port, path and query — so it stays a valid, parseable connection string
        (postgres://…, jdbc:…://…, amqp://…, http(s) credential/internal URLs).
        A format-string TEMPLATE (amqp://%s:%s@%s/%s, ${HOST}, {db}) is left
        untouched (it carries no real host; masking it orphans the args). A kept
        host (localhost / private IP / generic service name / allowlisted) with NO
        credentials is left as-is; credentials (userinfo) are always dropped."""
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                s = raw.decode("cp1251")
            except UnicodeDecodeError:
                return raw
        if is_template(s):
            return raw
        m = _SCHEME_AUTHORITY_RE.match(raw)
        if not m:
            return raw
        host = m.group("host")
        try:
            host_str = host.decode("utf-8").strip("[]")
        except UnicodeDecodeError:
            host_str = None
        if not m.group("userinfo") and host_str is not None and _is_kept_url_host(host_str, self._keep):
            return raw
        host_mask = hash12(self.salt, host).encode() + b".example.invalid"
        return m.group("scheme") + host_mask + raw[m.end("host"):]

    def _mask_if_luhn(self, m: "re.Match[bytes]", name: bytes) -> bytes:
        """Mask a card-shaped match only if its digits pass Luhn; otherwise leave it
        (numeric DATA, not a card)."""
        raw = m.group()
        if luhn_ok(raw.decode("ascii", "ignore")):
            return b"REDACTED_" + name.upper() + b"_" + hash12(self.salt, raw[:64]).encode()
        return raw

    def _mask_grouped(self, m: "re.Match[bytes]") -> bytes:
        """Replace ONLY the captured secret value (group 1) with REDACTED_<hash>,
        leaving the surrounding declaration (keyword, quotes, assignment) intact so
        the file still parses/compiles. Templates are left untouched."""
        whole = m.group(0)
        if m.lastindex is None or m.group(1) is None:
            return whole
        val = m.group(1)
        try:
            if is_template(val.decode("utf-8")):
                return whole
        except UnicodeDecodeError:
            pass
        s, e = m.start(1) - m.start(0), m.end(1) - m.start(0)
        return whole[:s] + b"REDACTED_" + hash12(self.salt, val).encode() + whole[e:]

    def _mask_url_param(self, m: "re.Match[bytes]") -> bytes:
        """Keep the "?name="/"&name=" prefix of a secret-bearing URL parameter and
        mask only its value → "?token=REDACTED_<hash>" (a still-valid URL query).
        A templated value ("?token={{$t}}") is left untouched."""
        raw = m.group(0)
        eq = raw.find(b"=")
        if eq < 0:
            return raw
        name, val = raw[: eq + 1], raw[eq + 1:]
        try:
            if is_template(val.decode("utf-8")):
                return raw
        except UnicodeDecodeError:
            pass
        return name + b"REDACTED_" + hash12(self.salt, val).encode()

    def _scrub_url_hosts_bytes(self, data: bytes) -> bytes:
        """Mask a URL's userinfo+host when the host is not universal public infra
        / kept (endpoint._is_kept_url_host) OR userinfo is present →
        `<hash>.example.invalid`, keeping scheme/path/query and the surrounding
        file structure intact (no `[...]` token, so YAML/XML stay parseable; a
        bracketed IPv6 host is captured whole so it never becomes `[[ipv6:…]]`).
        Runs over EVERY history blob — incl. SVG/oversized blobs the
        inventory-bound scan skips. A host that does not decode as UTF-8 (or any
        non-ASCII IDN host) is masked, not passed through."""
        def _repl(m: "re.Match[bytes]") -> bytes:
            scheme, userinfo, host = m.group(1), m.group(2), m.group(3)
            try:
                host_str = host.decode("utf-8")
            except UnicodeDecodeError:
                host_str = None
            if not userinfo and host_str is not None and _is_kept_url_host(host_str, self._keep):
                return m.group(0)
            return scheme + hash12(self.salt, host).encode() + b".example.invalid"

        return self._url_re.sub(_repl, data)

    def _scrub_public_ip_bytes(self, data: bytes) -> bytes:
        """Mask globally-routable IPv4/IPv6 literals (deployment fingerprints) with
        a VALID documentation-range literal (203.0.113.x / 2001:db8::x), KEEPING
        private/loopback/reserved/CGNAT/doc-range and allowlisted IPs.

        Using a real doc-range IP (not a `[ipv4:hash]` bracket marker) keeps
        docker-compose port-specs / k8s / nginx / YAML / JSON parseable where the
        marker broke them, and is itself non-global so a re-scan never re-flags it.
        This is the ONLY public-IP coverage for blobs the inventory-bound
        EndpointDetector scan skips (SVG, binary-allow, oversized text): the
        rulepack `ipv4` regex was removed (it over-masked private build infra), so
        this keep-aware, public-ONLY pass replaces it across every history blob.
        "Which IP is worth redacting" stays defined once in endpoint._is_public_ip.
        Runs LAST in the non-brand scrub, after any connection-string / URL pattern
        has claimed its full match."""
        def _repl(m: "re.Match[bytes]", masker, version_aware: bool) -> bytes:
            raw = m.group()
            try:
                value = raw.decode("ascii")
            except UnicodeDecodeError:
                return raw
            if value.lower() in self._keep:
                return raw
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return raw
            if not _is_public_ip(ip):
                return raw
            # A 4-part dotted version (AssemblyVersion="4.0.0.0", mscorlib
            # Version=4.0.0.0) is a valid public IPv4 — don't mask it as an IP.
            if version_aware:
                pre = m.string[max(0, m.start() - 28):m.start()].decode("ascii", "ignore")
                if in_version_context(pre, len(pre)):
                    return raw
            return masker(self.salt, raw)

        data = self._ipv4_re.sub(lambda m: _repl(m, doc_ipv4, True), data)
        data = self._ipv6_re.sub(lambda m: _repl(m, doc_ipv6, False), data)
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
