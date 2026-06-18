"""Brand-token variant expansion.

One brand token in the rulepack should catch every real-world spelling. The
dictionary / brand matchers are already case-insensitive substring matchers, so
*case* variants are redundant; this module generates the forms that case-folding
does NOT cover:

* **separator** variants for multi-word brands
  (``Acme Corp`` → ``acmecorp``, ``acme-corp``, ``acme_corp``, ``acme.corp`` …),
* a backstop **Latin↔Cyrillic transliteration** (discovery usually supplies both
  scripts already, so this only fills gaps), and
* **mojibake** — the double-encoded-cp1251 form Russian text takes when a
  UTF-8 byte stream is mis-decoded as Windows-1251 (``Яндекс`` → ``РЇРЅРґРµРєСЃ``).

``expand_term`` is pure and deterministic. Apply it once at brand-dictionary
construction so an operator writes ``Extyl`` (or ``Яндекс``) a single time.
"""
from __future__ import annotations

import re

# Minimum source length before the transliteration backstop runs. Short tokens
# transliterate to extremely common substrings (In→ин, On→он, vk→вк) that flood
# the substring matcher with false positives in Russian text.
_MIN_TRANSLIT_LEN = 4
# Unicode replacement char — a mojibake form containing it is a dead token (cp1251
# has undefined bytes, e.g. capital И's 0x98) that can never match a real leak.
_REPLACEMENT_CHAR = "�"

_SEPARATORS = ["", "-", "_", " ", "."]
_SPLIT_RE = re.compile(r"[\s\-_.]+")
# camelCase / PascalCase boundary (lower- or digit-then-upper), both scripts.
_CAMEL_RE = re.compile(r"(?<=[a-zа-яё0-9])(?=[A-ZА-ЯЁ])")
_CYRILLIC_RE = re.compile(r"[Ѐ-ӿ]")
_LATIN_RE = re.compile(r"[A-Za-z]")

# Cyrillic → Latin, longest keys are irrelevant (single chars), applied per-char.
_CYR_TO_LAT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}
# Latin → Cyrillic, longest digraphs first (greedy). Backstop only. Covers all
# 26 Latin letters so a single-script Latin term transliterates without leaving
# mixed-script residue (Box→Бокс, not Боx).
_LAT_TO_CYR = [
    ("shch", "щ"), ("zh", "ж"), ("kh", "х"), ("ts", "ц"), ("ch", "ч"),
    ("sh", "ш"), ("yu", "ю"), ("ya", "я"), ("yo", "ё"), ("a", "а"),
    ("b", "б"), ("v", "в"), ("g", "г"), ("d", "д"), ("e", "е"), ("z", "з"),
    ("i", "и"), ("j", "й"), ("k", "к"), ("l", "л"), ("m", "м"), ("n", "н"),
    ("o", "о"), ("p", "п"), ("q", "к"), ("r", "р"), ("s", "с"), ("t", "т"),
    ("u", "у"), ("f", "ф"), ("w", "в"), ("x", "кс"), ("y", "ы"), ("c", "к"),
    ("h", "х"),
]


def _to_mojibake(text: str) -> str:
    """UTF-8 bytes mis-decoded as cp1251 — the classic double-encoding leak."""
    return text.encode("utf-8").decode("cp1251", errors="replace")


def _translit_cyr_to_lat(text: str) -> str:
    out = []
    for ch in text:
        lower = ch.lower()
        rep = _CYR_TO_LAT.get(lower)
        if rep is None:
            out.append(ch)
        elif ch.isupper():
            out.append(rep.capitalize())
        else:
            out.append(rep)
    return "".join(out)


def _translit_lat_to_cyr(text: str) -> str:
    out = []
    i = 0
    low = text.lower()
    while i < len(text):
        for lat, cyr in _LAT_TO_CYR:
            if low.startswith(lat, i):
                out.append(cyr.upper() if text[i].isupper() else cyr)
                i += len(lat)
                break
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _split_tokens(term: str) -> list[str]:
    """Split on explicit separators AND camelCase/PascalCase boundaries, so
    ``AcmeCorp`` and ``acme-corp`` both yield ``[Acme, Corp]``."""
    tokens: list[str] = []
    for part in _SPLIT_RE.split(term):
        if not part:
            continue
        tokens.extend(t for t in _CAMEL_RE.split(part) if t)
    return tokens


def _separator_variants(term: str) -> set[str]:
    tokens = _split_tokens(term)
    if len(tokens) < 2:
        return {term}
    forms: set[str] = {term}
    casings = [
        tokens,
        [t.lower() for t in tokens],
        [t.capitalize() for t in tokens],
    ]
    for toks in casings:
        for sep in _SEPARATORS:
            forms.add(sep.join(toks))
    return forms


def expand_term(term: str) -> set[str]:
    """Return ``term`` plus all separator / transliteration / mojibake variants.

    Empty / whitespace-only input yields an empty set.
    """
    term = term.strip()
    if not term:
        return set()

    forms: set[str] = {term}
    forms |= _separator_variants(term)

    # Transliteration backstop: single-script terms only, and only for terms
    # long enough that the result is a distinctive token (a length guard, plus a
    # mixed-script skip so a half-transliterated garbage token is never emitted).
    for base in list(forms):
        if len(base) < _MIN_TRANSLIT_LEN:
            continue
        has_cyr = bool(_CYRILLIC_RE.search(base))
        has_lat = bool(_LATIN_RE.search(base))
        if has_cyr and not has_lat:
            t = _translit_cyr_to_lat(base)
            if not _CYRILLIC_RE.search(t):
                forms.add(t)
        elif has_lat and not has_cyr:
            t = _translit_lat_to_cyr(base)
            if not _LATIN_RE.search(t):
                forms.add(t)

    # Mojibake of every Cyrillic-bearing form (incl. transliterated-to-Cyrillic),
    # skipping any form whose cp1251 round-trip hit an undefined byte (U+FFFD) —
    # that token is dead and could never match a real double-encoded leak.
    for base in list(forms):
        if _CYRILLIC_RE.search(base):
            moji = _to_mojibake(base)
            if _REPLACEMENT_CHAR not in moji:
                forms.add(moji)

    return {f for f in forms if f}
