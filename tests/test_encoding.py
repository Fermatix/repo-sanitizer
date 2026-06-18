from __future__ import annotations

import codecs

from repo_sanitizer.encoding import decode_bytes_detect, read_text_detect


def test_utf8_detected():
    text, enc = decode_bytes_detect("Привет мир".encode("utf-8"))
    assert text == "Привет мир"
    assert enc == "utf-8"


def test_ascii_is_utf8():
    text, enc = decode_bytes_detect(b"hello = 1")
    assert text == "hello = 1"
    assert enc == "utf-8"


def test_cp1251_detected_and_decoded():
    raw = "Привет мир".encode("cp1251")
    text, enc = decode_bytes_detect(raw)
    assert text == "Привет мир"  # not mojibake
    assert enc == "cp1251"
    assert "�" not in text


def test_utf8_bom_detected():
    raw = codecs.BOM_UTF8 + "Привет".encode("utf-8")
    text, enc = decode_bytes_detect(raw)
    assert text == "Привет"
    assert enc == "utf-8-sig"


def test_read_text_detect_cp1251(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes("Москерам".encode("cp1251"))
    text, enc = read_text_detect(p)
    assert text == "Москерам"
    assert enc == "cp1251"


def test_cp1251_roundtrip_no_corruption(tmp_path):
    # Fix B headline guarantee: a cp1251 file read then written back in its
    # detected encoding is preserved. The old `utf-8, errors="replace"` read
    # plus `write_text(..., "utf-8")` permanently destroyed the Cyrillic.
    p = tmp_path / "legacy.php"
    original = "<?php $brand = 'Москерам'; // комментарий\n".encode("cp1251")
    p.write_bytes(original)

    text, enc = read_text_detect(p)
    # Simulate a redaction that rewrites only ASCII (as the HMAC masks do).
    redacted = text.replace("Москерам", "TERM_abc123")
    p.write_text(redacted, encoding=enc, errors="replace")

    roundtrip = p.read_bytes().decode("cp1251")
    assert "комментарий" in roundtrip  # untouched Cyrillic preserved
    assert "TERM_abc123" in roundtrip
    assert "�" not in roundtrip
