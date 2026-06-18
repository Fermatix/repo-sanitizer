"""Encoding-aware text I/O.

Files are decoded with detection rather than a hardcoded ``utf-8`` so that
legacy single-byte encodings (notably Windows-1251 / cp1251, common in Russian
Bitrix/PHP code) are read correctly instead of being mangled into U+FFFD before
any detector runs. The detected encoding label is returned alongside the text so
callers can write the file back in its ORIGINAL encoding and avoid lossily
re-encoding the whole file to UTF-8 (which would permanently destroy Cyrillic).
"""

from __future__ import annotations

import codecs
from pathlib import Path

# BOM-prefixed encodings, longest BOM first so utf-32 wins over utf-16
# (the utf-32-LE BOM ``FF FE 00 00`` also starts with the utf-16-LE BOM).
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

# Fallback for non-UTF-8 text. cp1251 is the right guess for our domain
# (Russian/Bitrix). Single-byte 0xC0-0xFF Cyrillic is invalid as standalone
# UTF-8, so a strict utf-8 decode cleanly fails over to this; genuine UTF-8
# decodes first and wins.
_LEGACY_FALLBACK = "cp1251"


def decode_bytes_detect(raw: bytes) -> tuple[str, str]:
    """Decode file bytes, detecting the encoding.

    Returns ``(text, encoding_label)``. Order: a BOM-indicated encoding, then
    strict UTF-8, then the legacy cp1251 fallback, then UTF-8 with
    ``errors="replace"`` as a last resort (so this never raises). The label is
    suitable for writing the file back in its original encoding.
    """
    for bom, enc in _BOMS:
        if raw.startswith(bom):
            try:
                return raw.decode(enc), enc
            except (UnicodeDecodeError, LookupError):
                break  # malformed despite the BOM — fall through to sniffing

    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    try:
        return raw.decode(_LEGACY_FALLBACK), _LEGACY_FALLBACK
    except (UnicodeDecodeError, LookupError):
        pass

    return raw.decode("utf-8", errors="replace"), "utf-8"


def read_text_detect(path: str | Path) -> tuple[str, str]:
    """Read a file as text with encoding detection (see ``decode_bytes_detect``)."""
    return decode_bytes_detect(Path(path).read_bytes())
