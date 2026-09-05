"""Mask literal config values by key name, independently of secret entropy.

Adapted from whole-repo-anon's conf_keys engine. No repository or CLI dependency:
callers supply the path and bytes, and own traversal of working trees/history.
The extra pass is opt-in through rulepack mask_config_values. Existing detector
passes still run; this module preserves their REDACTED placeholders.
"""
from __future__ import annotations

import os
import re
import html
import shlex

import yaml

from repo_sanitizer.buildsafe import is_template

KEY_WORDS = (r"(?:pass(?:word|wd|phrase)|pwd|secret(?:[_-]?key(?:[_-]?base)?)?|token|api[_-]?key|apikey|"
             r"access[_-]?key|private[_-]?key|client[_-]?secret|dsn|connection[_-]?string|database[_-]?url|"
             r"db[_-]?url|redis[_-]?url|amqp[_-]?url|broker[_-]?url|mongo(?:db)?[_-]?ur[il]|webhook(?:[_-]?url)?|"
             r"salt|signing[_-]?key|encryption[_-]?key|master[_-]?key|app[_-]?key|license[_-]?key|auth[_-]?token|"
             r"bot[_-]?token|jwt[_-]?secret|credentials?)")
_KEY = rf"(?<![\w.\-])(?P<key>[\w.\-]*?{KEY_WORDS})"
_ASSIGN = rf"""(?P<pre>(?P<kq>["']?){_KEY}(?P=kq)\s*(?::|=>|=)\s*)"""
# Backslashes must only match the escape branch. Overlapping alternatives here
# make an unterminated quoted value exponentially expensive.
RX_Q = re.compile(_ASSIGN + r"""(?P<vq>["'])(?P<val>(?:\\[^\r\n]|(?!(?P=vq))[^\\\r\n])*)(?P=vq)""", re.I)
RX_TRIPLE = re.compile(_ASSIGN + "(?P<vq>\"\"\"|''')"
                       + r"(?P<val>(?:\\[\s\S]|(?!(?P=vq))[^\\])*)(?P=vq)", re.I)
# TOML literal strings have no backslash escapes. End at the last delimiter
# when a multiline literal ends with four/five quotes (one/two belong to it).
RX_TOML_LITERAL = re.compile(_ASSIGN + r"(?P<vq>'''|')(?P<val>(?:(?!(?P=vq)(?!'))[\s\S])*)(?P=vq)(?!')", re.I)
_BARE_ASSIGN = rf"""(?P<pre>[ \t]*(?:export[ \t]+|ENV[ \t]+|ARG[ \t]+)?(?:-[ \t]+)?{_KEY}[ \t]*[:=][ \t]*)"""
RX_B = re.compile(rf"""^{_BARE_ASSIGN}(?P<val>[^\s"'#;][^\r\n]*?)(?P<post>[ \t]+[#;].*|[ \t]*)$""", re.I)
# Java properties only treat #/! at the START of a line as comments.
RX_PROPERTY = re.compile(rf"""^{_BARE_ASSIGN}(?P<val>[^\s"'][^\r\n]*?)(?P<post>[ \t]*)$""", re.I)
RX_X = re.compile(rf"(?P<pre><(?P<tag>[\w:.\-]*?{KEY_WORDS})(?:\s[^>]*)?>)(?P<val>[^<]+)(?P<post></(?P=tag)>)", re.I)
RX_CS = re.compile(r"(?P<pre>(?<![\w.\-])(?:password|pwd|passwd)\s*=\s*)(?P<val>[^;\"'\s<>]{2,})", re.I)
CS_HINT = re.compile(r"(?i)(server|data source|host|user id|uid|database|initial catalog)\s*=")
RX_URL = re.compile(r"(?P<pre>\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]*:)(?P<val>[^@\s'\"/]+)(?P<post>@)", re.I)   # empty user ok

PLACEHOLDERS = {"null", "none", "nil", "true", "false", "yes", "no", "on", "off", "redacted", "changeme", "change_me",
                "change-me", "secret", "password", "example", "dummy", "placeholder", "xxx", "test", "string", "value",
                "todo", "empty", "undefined", "n/a", "-", "same-origin", "include", "omit", "basic", "bearer", "digest",
                "required", "optional", "auto", "default", "disabled", "enabled"}
# keys that END with a sensitive word but are references / metadata, never the secret itself
NONSECRET_KEY = re.compile(r"(existing[_-]?secret|secret[_-]?name|secret[_-]?ref|secret[_-]?key[_-]?ref|[_-]ref|[_-]id|"
                           r"[_-]file|[_-]path|[_-]env|[_-]header|[_-]endpoint|[_-]name|[_-]label|[_-]type|[_-]length|"
                           r"[_-]ttl|[_-]expires?|[_-]count|[_-]enabled|[_-]required)$", re.I)
RX_UI = re.compile(r"(?P<pre>\b[a-z][a-z0-9+.\-]*://)(?P<ui>[^/\s@'\"]+)(?P<post>@)", re.I)   # whole userinfo (user:pw / token)
_URLISH = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
_LABEL = re.compile(r"^[^\W\d_]+(?:[ ,.!?][ ]*[^\W\d_]+)+[.!?]?$")     # SPACE-separated alphabetic phrase = UI label (django-x is not)
_NONLATIN_WORD = re.compile(r"^[^\W\d_a-zA-Z]+$")                       # a single Cyrillic/… word = label, not a secret
I18N_RE = re.compile(r"(^|/)(locales?|i18n|l10n|lang|langs|translations?|messages|strings)(/|$)", re.I)
_REF = re.compile(r"^(\$\{|\$\(|\$[A-Za-z_]|%\(|%[A-Za-z_]+%|\{\{|<%|\{%|os\.|env\(|getenv|process\.env|env\[|ENV\[|"
                  r"System\.getenv|@Value|!|\||>|\[|\{|<|/|\./|\.\./|~/|file:|classpath:|env:|vault:|secretref:|arn:|"
                  r"sm://|kms:|projects/|\(\(|@@)", re.I)

CONF_EXT = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".env", ".plist",
            ".xml", ".tf", ".tfvars", ".hcl", ".jsonc", ".json5", ".neon", ".editorconfig"}
LINE_EXT = {".env", ".properties", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".txt"}
CODE_EXT = {".py", ".php", ".js", ".ts", ".rb", ".go", ".java", ".kt", ".cs", ".swift", ".dart", ".mjs", ".cjs", ".scala"}
_CONF_STEM = re.compile(r"^(app[_-]?|local[_-]?|base[_-]?|prod(?:uction)?[_-]?|dev(?:elopment)?[_-]?|test(?:ing)?[_-]?|staging[_-]?)?"
                        r"(config|configs|configuration|settings|local_settings|database|databases|secrets?|credentials|env|"
                        r"environment|environments|constants|params|parameters|appsettings|application)[\w.\-]*$", re.I)
_SKIP_DIRS = {"node_modules", "vendor", "bower_components", ".git", "dist", "build", "__pycache__", "third_party", "3rdparty"}
_SKIP_BASE = {"package-lock.json", "composer.lock", "yarn.lock", "poetry.lock", "pnpm-lock.yaml", "cargo.lock",
              "gemfile.lock", "packages.lock.json", "flake.lock"}
MAX_BLOB = 2 * 1024 * 1024
MASK = "REDACTED"
ALLOW_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def config_path(path: str, allow_suffixes=ALLOW_SUFFIXES) -> str:
    """Classify allowed examples using their underlying file format."""
    for suffix in allow_suffixes:
        if suffix and path.endswith(suffix):
            return path[:-len(suffix)]
    return path


def is_conf_path(path: str) -> bool:
    p = path.replace("\\", "/")
    parts = p.lower().split("/")
    base = parts[-1]
    if not base or any(seg in _SKIP_DIRS for seg in parts[:-1]):
        return False
    if base in _SKIP_BASE or base.endswith((".min.js", ".schema.json", ".lock", ".map", ".po", ".pot", ".strings")):
        return False
    if I18N_RE.search("/".join(parts[:-1])):        # translation resources: "password": "Пароль" is a label
        return False
    stem, ext = os.path.splitext(base)
    if base.startswith(".env") or base.startswith("dockerfile") or ext in CONF_EXT:
        return True
    if ext in CODE_EXT:
        if _CONF_STEM.match(stem):
            return True
        if any(d in ("config", "configs", "settings", "conf", "environments") for d in parts[:-1]):
            return True
    return False


def _is_line_format(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    return base.startswith(".env") or base.startswith("dockerfile") or os.path.splitext(base)[1] in LINE_EXT


def is_real(val: str) -> bool:
    v = (val or "").strip()
    if len(v) < 2:
        return False
    low = v.lower()
    if low in PLACEHOLDERS or _REF.match(v):
        return False
    if re.fullmatch(r"[x*#.\-_=\s0]+", low):
        return False
    if low.startswith(("your_", "your-", "your ", "redacted", "changeme", "insert_", "replace_", "todo", "fixme", "<", "***")):
        return False
    if v.isdigit() and len(v) < 6:
        return False
    # relative file path (creds/x.json, config/keys/a.pem): first segment without a dot AND a file extension —
    # base64 secrets with '/' (wJalrXUtnFEMI/K7MDENG/…) have no extension and stay masked
    if "/" in v and re.fullmatch(r"[\w\-~]+(/[\w.\-]+)+", v) and re.search(r"\.[A-Za-z0-9]{1,6}$", v):
        return False
    if _LABEL.fullmatch(v) or _NONLATIN_WORD.fullmatch(v):
        return False
    return True


def decide(key: str, val: str) -> str | None:
    """Replacement for `val` under `key`, or None to leave it. URL values keep scheme/host: only the
    userinfo is masked (whole value only for webhook-style keys whose secret sits in the path)."""
    if NONSECRET_KEY.search(key or "") or not is_real(val):
        return None
    if _URLISH.match(val.strip()):
        if re.search(r"webhook", key or "", re.I):
            return MASK
        new = RX_UI.sub(lambda m: f"{m.group('pre')}{_mask_userinfo(m.group('ui'))}{m.group('post')}", val)
        return new if new != val else None
    if is_template(val):
        return None
    return MASK


def _mask_userinfo(userinfo: str) -> str:
    """Preserve dynamic credentials, including mixed literal/template URLs."""
    user, sep, password = userinfo.partition(":")
    if not sep:
        return userinfo if is_template(userinfo) or not is_real(userinfo) else MASK
    if is_template(password) or not is_real(password):
        return userinfo
    return user + ":" + MASK if is_template(user) else MASK


def _yaml_scalars(text: str) -> tuple[str, int, bool]:
    """Use YAML source marks for complete escaped/folded/block scalar spans.

    No serialization of the document: only the sensitive scalar is replaced.
    Unsupported template syntax falls back to the bounded lexical handlers.
    """
    try:
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        documents = list(yaml.compose_all(text, Loader=loader))
        tokens = list(yaml.scan(text, Loader=loader))
    except yaml.YAMLError:
        return text, 0, False
    scalars = {token.end_mark.index: token for token in tokens if isinstance(token, yaml.ScalarToken)}
    tags = [token for token in tokens if isinstance(token, yaml.TagToken)]
    replacements = {}
    changed_scalars = {}
    seen = set()

    def walk(node, sequence_item=False, format_hint="config.conf"):
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if (isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode)
                        and re.fullmatch(_KEY, key.value, re.I)
                        and not value.tag.startswith("!")):
                    new = decide(key.value, value.value)
                    if new is not None and new != value.value:
                        end = value.end_mark.index
                        start = scalars[end].start_mark.index
                        scalar = text[start:end]
                        # Scalar tokens exclude anchors, tags and comments,
                        # including those on previous lines. Explicit typed
                        # secrets become strings so REDACTED remains valid YAML.
                        if value.tag != "tag:yaml.org,2002:str":
                            for tag in tags:
                                if value.start_mark.index <= tag.start_mark.index < start:
                                    replacements[(tag.start_mark.index, tag.end_mark.index)] = "!!str"
                        if value.style in ("|", ">"):
                            lines = scalar.splitlines(keepends=True)
                            indent = next((re.match(r"[ \t]*", line).group()
                                           for line in lines[1:] if line.strip()), "  ")
                            eol = "\r\n" if lines[0].endswith("\r\n") else "\n"
                            rendered = lines[0] + indent + new
                            if scalar.endswith(("\n", "\r")):
                                rendered += eol
                        elif value.style == "'":
                            rendered = "'" + new.replace("'", "''") + "'"
                        elif value.style == '"':
                            import json
                            rendered = json.dumps(new, ensure_ascii=False)
                        else:
                            rendered = new
                        replacements[(start, end)] = rendered
                        changed_scalars[(start, end)] = 1
                hint = key.value if isinstance(key, yaml.ScalarNode) else "config.conf"
                walk(value, format_hint=hint)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                walk(value, sequence_item=True)
        elif isinstance(node, yaml.ScalarNode) and node.tag == "tag:yaml.org,2002:str":
            end = node.end_mark.index
            token = scalars.get(end)
            if token is None:
                return  # implicit empty scalar
            start = token.start_mark.index
            if (start, end) in changed_scalars:
                return
            raw = text[start:end]
            if node.style in ("|", ">"):
                # ConfigMaps commonly embed another config in a YAML block.
                # Work on the physical body to retain folding, indentation
                # and CRLF, rather than serializing its decoded scalar value.
                lines = raw.splitlines(keepends=True)
                hint = format_hint if os.path.splitext(format_hint)[1] in CONF_EXT | CODE_EXT else "config.conf"
                body, count = mask_text("".join(lines[1:]), hint)
                rendered = lines[0] + body
            elif sequence_item:
                # docker-compose environment: ["PASSWORD=pw3"].
                rendered, count = mask_text(node.value, "config.properties")
                if node.style == "'":
                    rendered = "'" + rendered.replace("'", "''") + "'"
                elif node.style == '"':
                    import json
                    rendered = json.dumps(rendered, ensure_ascii=False)
            else:
                return
            if count:
                replacements[(start, end)] = rendered
                changed_scalars[(start, end)] = count
    for document in documents:
        walk(document)
    for (start, end), replacement in sorted(replacements.items(), reverse=True):
        text = text[:start] + replacement + text[end:]
    return text, sum(changed_scalars.values()), True


def _properties_continuations(text: str) -> tuple[str, int]:
    """Mask one logical property without turning its tail into another key."""
    lines = text.splitlines(keepends=True)
    count = 0
    i = 0
    while i < len(lines):
        body = lines[i].rstrip("\r\n")
        start = i
        parts = [body]
        while len(body) - len(body.rstrip("\\")) & 1 and i + 1 < len(lines):
            parts[-1] = parts[-1][:-1]
            i += 1
            body = lines[i].rstrip("\r\n")
            parts.append(body.lstrip())
        if i > start:
            match = RX_PROPERTY.match("".join(parts))
            if match:
                new = decide(match.group("key"), match.group("val"))
                if new is not None and new != match.group("val"):
                    first = lines[start].rstrip("\r\n")
                    lines[start] = match.group("pre") + new + match.group("post") + lines[start][len(first):]
                    for j in range(start + 1, i + 1):
                        # Blank the consumed physical lines; keep CRLF/LF.
                        old = lines[j].rstrip("\r\n")
                        lines[j] = lines[j][len(old):]
                    count += 1
        i += 1
    return "".join(lines), count


def _xml_key_values(text: str) -> tuple[str, int]:
    """Handle .NET appSettings attributes and plist key/string pairs."""
    count = 0
    attr = re.compile(r"""(?P<key>[\w:.-]+)\s*=\s*(?P<q>["'])(?P<val>(?:(?!(?P=q))[\s\S])*)(?P=q)""")
    def add(match):
        nonlocal count
        raw = match.group()
        attrs = {m.group("key"): m for m in attr.finditer(raw)}
        key = attrs.get("key")
        value = attrs.get("value")
        if key and value and re.fullmatch(_KEY, html.unescape(key.group("val")), re.I):
            new = decide(html.unescape(key.group("val")), html.unescape(value.group("val")))
            if new is not None and new != html.unescape(value.group("val")):
                count += 1
                return raw[:value.start("val")] + html.escape(new, quote=True) + raw[value.end("val"):]
        return raw
    text = re.sub(r"""<add\b(?:[^"'<>]|"[^"]*"|'[^']*')*/?>""", add, text)
    def plist(match):
        nonlocal count
        key, val = html.unescape(match.group("key")), html.unescape(match.group("val"))
        if re.fullmatch(_KEY, key, re.I):
            new = decide(key, val)
            if new is not None and new != val:
                count += 1
                return match.group("pre") + html.escape(new, quote=False) + match.group("post")
        return match.group()
    text = re.sub(r"(?P<pre><key>(?P<key>[^<]+)</key>\s*<string>)(?P<val>[^<]*)(?P<post></string>)", plist, text)
    return text, count


def _docker_values(text: str) -> tuple[str, int]:
    """Replace complete ENV/ARG values, including joined quote fragments.

    Parse logical instructions before the generic quoted handler can redact
    only one fragment. Keep sibling assignments and continuation line endings.
    """
    word = re.compile(r"""(?:\\(?:\r\n|[\s\S])|"(?:\\[\s\S]|[^"\\])*"|'[^']*'|[^\s"'\\])+""")
    lines = text.splitlines(keepends=True)
    out = []
    count = 0
    i = 0
    while i < len(lines):
        instruction = lines[i]
        while lines[i].rstrip("\r\n").endswith("\\") and i + 1 < len(lines):
            i += 1
            instruction += lines[i]
        i += 1
        head = re.match(r"^\s*(?:ENV|ARG)\s+", instruction, re.I)
        replacements = []
        if head:
            for token in word.finditer(instruction, head.end()):
                key, sep, raw = token.group().partition("=")
                if not sep or not re.fullmatch(_KEY, key, re.I) or not raw:
                    continue
                logical = re.sub(r"\\\r?\n", "", raw)
                values = shlex.split(logical)
                if len(values) != 1:
                    continue
                value = values[0]
                new = decide(key, value)
                if new is None or new == value:
                    continue
                rendered = shlex.quote(new)
                if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
                    rendered = raw[0] + new + raw[-1]
                rendered += "".join(re.findall(r"\\\r?\n", raw))
                replacements.append((token.start() + len(key) + 1, token.end(), rendered))
        else:
            # Preserve the inherited quoted-assignment handling in RUN and
            # other instructions. Only ENV/ARG need whole shell-value spans.
            def quoted(match):
                nonlocal count
                new = decide(match.group("key"), match.group("val"))
                if new is not None and new != match.group("val"):
                    count += 1
                    return match.group("pre") + match.group("vq") + new + match.group("vq")
                return match.group()
            instruction = RX_TRIPLE.sub(quoted, instruction)
            instruction = RX_Q.sub(quoted, instruction)
        for start, end, replacement in reversed(replacements):
            instruction = instruction[:start] + replacement + instruction[end:]
        count += len(replacements)
        out.append(instruction)
    return "".join(out), count


def mask_text(text: str, path: str) -> tuple[str, int]:
    n = 0
    parsed_yaml = False
    line_fmt = _is_line_format(path)
    is_docker = path.rsplit("/", 1)[-1].lower().startswith("dockerfile")
    if is_docker:
        text, count = _docker_values(text)
        n += count
    is_xml = path.lower().endswith((".xml", ".plist", ".config", ".csproj", ".xaml"))
    if path.lower().endswith((".yaml", ".yml")):
        text, count, parsed_yaml = _yaml_scalars(text)
        n += count
    if path.lower().endswith(".properties"):
        text, count = _properties_continuations(text)
        n += count
    if is_xml:
        text, count = _xml_key_values(text)
        n += count
    def q(m):
        nonlocal n
        new = decide(m.group("key"), m.group("val"))
        if new is not None and new != m.group("val"):
            n += 1
            return f"{m.group('pre')}{m.group('vq')}{new}{m.group('vq')}"
        return m.group(0)
    # Complete triple-quoted literals first, then ordinary quotes. Run against
    # the whole text so whitespace between a key and value may span lines.
    if not parsed_yaml and not is_docker:
        if path.lower().endswith(".toml"):
            text = RX_TOML_LITERAL.sub(q, text)
        text = RX_TRIPLE.sub(q, text)
        text = RX_Q.sub(q, text)
    out = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n"); eol = line[len(body):]
        if body and any(ch in body for ch in (":", "=", "<")):
            if line_fmt and not parsed_yaml and not is_docker:
                bare = RX_PROPERTY if path.lower().endswith(".properties") else RX_B
                m = bare.match(body)
                if m:
                    new = decide(m.group("key"), m.group("val"))
                    if new is not None and new != m.group("val"):
                        n += 1
                        body = f"{m.group('pre')}{new}{m.group('post')}"
            if is_xml and "<" in body:
                def x(m):
                    nonlocal n
                    new = decide(m.group("tag"), m.group("val"))
                    if new is not None and new != m.group("val"):
                        n += 1
                        return f"{m.group('pre')}{new}{m.group('post')}"
                    return m.group(0)
                body = RX_X.sub(x, body)
            if ";" in body and CS_HINT.search(body):
                def cs(m):
                    nonlocal n
                    if is_real(m.group("val")) and not is_template(m.group("val")):
                        n += 1
                        return f"{m.group('pre')}{MASK}"
                    return m.group(0)
                body = RX_CS.sub(cs, body)
            if "://" in body and "@" in body:
                def u(m):
                    nonlocal n
                    if is_real(m.group("val")) and not is_template(m.group("val")):
                        n += 1
                        return f"{m.group('pre')}{MASK}{m.group('post')}"
                    return m.group(0)
                body = RX_URL.sub(u, body)
        out.append(body + eol)
    return "".join(out), n


class ConfigMasker:
    """One pass's aggregate counters; never retains original values or paths.

    History callers deduplicate by (original blob, path, mode); working-tree counters
    count file visits across redaction/convergence passes. Skipped candidates
    remain subject to the sanitizer's existing detection/redaction passes.
    """

    def __init__(self, allow_suffixes=ALLOW_SUFFIXES, stats: dict | None = None):
        self.allow_suffixes = tuple(allow_suffixes)
        self.stats = stats if stats is not None else {}
        for key in ("candidates", "files_changed", "values_masked", "skipped_large", "skipped_path",
                    "skipped_binary", "skipped_encoding"):
            self.stats.setdefault(key, 0)

    def path(self, path: str) -> str:
        return config_path(path, self.allow_suffixes)

    def accepts(self, path: str) -> bool:
        path = self.path(path)
        base = path.rsplit("/", 1)[-1]
        # Count recognizable configs excluded by the inherited classifier too,
        # so an unsupported extension or vendored config is visible in reports.
        return bool(is_conf_path(path) or is_conf_path(base)
                    or re.match(r"^(config|settings|application|database)\.", base, re.I))

    def skip_large(self) -> None:
        self.stats["candidates"] += 1
        self.stats["skipped_large"] += 1

    def mask(self, data: bytes, path: str) -> bytes:
        if not self.accepts(path):
            return data
        path = self.path(path)
        if not is_conf_path(path):
            self.stats["candidates"] += 1
            self.stats["skipped_path"] += 1
            return data
        if len(data) > MAX_BLOB:
            self.skip_large()
            return data
        self.stats["candidates"] += 1
        if b"\x00" in data[:8192]:
            self.stats["skipped_binary"] += 1
            return data
        for enc in ("utf-8", "cp1251"):
            try:
                text = data.decode(enc)
            except UnicodeDecodeError:
                continue
            new, count = mask_text(text, path)
            if not count:
                return data
            # Replacements are ASCII, so the original encoding round-trips.
            result = new.encode(enc)
            self.stats["files_changed"] += 1
            self.stats["values_masked"] += count
            return result
        self.stats["skipped_encoding"] += 1
        return data
