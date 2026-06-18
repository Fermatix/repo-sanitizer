from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_sanitizer.redaction.history_ops import (
    Scrubber,
    apply_brand_map,
    apply_brand_map_bytes,
    compile_brand_map,
    load_brand_map,
)
from repo_sanitizer.rulepack import load_rulepack

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
SALT = b"test-salt-12345"


@pytest.fixture(scope="module")
def pii_defs() -> list:
    rp = load_rulepack(RULES_DIR)
    return [(p.name, p.pattern.pattern) for p in rp.pii_patterns]


class _Blob:
    """Minimal stand-in for git_filter_repo's Blob (just a mutable .data)."""

    def __init__(self, data: bytes) -> None:
        self.data = data


# ── non-brand scrubbing (Pass-1) ───────────────────────────────────────────────

def test_message_email_masked_to_invalid_domain(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"Contact john.doe@corp.com for details")
    assert b"@example.invalid" in out
    assert b"corp.com" not in out
    assert b"john.doe" not in out


def test_message_email_scrub_is_idempotent(pii_defs):
    """The @example.invalid mask must not be re-matched (rulepack (?!invalid\\b))."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    once = scr.message(b"mail me at jane@acme.org now")
    twice = scr.message(once)
    assert once == twice


def test_message_phone_masked(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"call +14155550123 tomorrow")
    assert b"+14155550123" not in out
    assert b"+0000000000" in out


def test_message_pii_pattern_masked(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"key AKIAIOSFODNN7EXAMPLE leaked")
    assert b"AKIAIOSFODNN7EXAMPLE" not in out
    assert b"[aws_access_key_id:" in out


def test_secret_literal_scrubbed_in_message_and_blob(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["supersecretvalue"])
    msg = scr.message(b"token=supersecretvalue end")
    assert b"supersecretvalue" not in msg
    assert b"REDACTED_" in msg

    blob = _Blob(b"X = 'supersecretvalue'\n")
    scr.blob(blob)
    assert b"supersecretvalue" not in blob.data
    assert b"REDACTED_" in blob.data


def test_secret_containing_email_fully_masked(pii_defs):
    """A secret literal that embeds an email must be masked as a whole (secrets
    apply before PII), leaving no high-entropy remainder."""
    secret = "abc123ops@corp.com_tail9876"
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=[secret])
    out = scr.message(b"X = " + secret.encode())
    assert secret.encode() not in out
    assert b"abc123" not in out  # the non-email remainder is gone too
    assert b"_tail9876" not in out
    assert b"REDACTED_" in out


def test_person_literal_scrubbed(pii_defs):
    """NER person names collected on the working tree are scrubbed from blobs and
    messages (→ ANON_PER_), closing the filter-repo worktree-reset leak."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, person_literals=["Margaret Thatcher"])
    msg = scr.message(b"Reviewed by Margaret Thatcher last week")
    assert b"Margaret Thatcher" not in msg
    assert b"ANON_PER_" in msg

    blob = _Blob(b"# author: Margaret Thatcher\nx = 1\n")
    scr.blob(blob)
    assert b"Margaret Thatcher" not in blob.data
    assert b"ANON_PER_" in blob.data


def test_person_literal_cp1251(pii_defs):
    """A Cyrillic person name in a cp1251 blob must be scrubbed too (literals are
    matched in both utf-8 and cp1251 byte forms)."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, person_literals=["Иван Петров"])
    blob = _Blob("// автор: Иван Петров\n".encode("cp1251"))
    scr.blob(blob)
    assert "Иван Петров".encode("cp1251") not in blob.data
    assert b"ANON_PER_" in blob.data


def test_blob_skips_binary(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["supersecretvalue"])
    original = b"\x00\x01supersecretvalue\x02"
    blob = _Blob(original)
    scr.blob(blob)
    assert blob.data == original  # null byte → treated as binary, untouched


def test_brands_not_scrubbed_in_pass1(pii_defs):
    """Pass-1 has no brand map → brands stay (detection-only worklist)."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"Extyl ships the product")
    assert b"Extyl" in out


def test_author_callbacks(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    name = scr.author_name(b"John Doe")
    email = scr.author_email(b"john@corp.com")
    assert name.startswith(b"Author_")
    assert email.startswith(b"author_") and email.endswith(b"@example.invalid")
    # deterministic under a fixed salt
    assert scr.author_name(b"John Doe") == name


# ── brand map (Pass-3) ─────────────────────────────────────────────────────────

def test_brand_map_regex_replaces_all_cases():
    scr = Scrubber(
        SALT,
        brand_map_rows=[{"pattern": r"(?i)\bextyl\b", "replacement": "Acme1", "is_regex": True}],
    )
    out = scr.message(b"Extyl and EXTYL and extyl")
    assert b"Extyl" not in out and b"EXTYL" not in out and b"extyl" not in out
    assert out.count(b"Acme1") == 3


def test_brand_map_longest_pattern_first():
    compiled = compile_brand_map(
        [
            {"pattern": "ext", "replacement": "X", "is_regex": False},
            {"pattern": "extyl", "replacement": "Y", "is_regex": False},
        ]
    )
    # 'extyl' (len 5) must run before 'ext' (len 3), else it becomes 'Xyl'
    assert apply_brand_map("extyl", compiled) == "Y"


def test_brand_map_preserve_case():
    compiled = compile_brand_map(
        [{"pattern": "extyl", "replacement": "acme", "is_regex": False, "preserve_case": True}]
    )
    assert apply_brand_map("Extyl EXTYL extyl", compiled) == "Acme ACME acme"


def test_brand_map_replacement_is_literal_not_template():
    # A replacement containing regex backref syntax must stay literal.
    compiled = compile_brand_map(
        [{"pattern": "foo", "replacement": r"A\1B&", "is_regex": False}]
    )
    assert apply_brand_map("foo", compiled) == r"A\1B&"


def test_apply_brand_map_bytes_skips_true_binary():
    compiled = compile_brand_map([{"pattern": "x", "replacement": "y", "is_regex": False}])
    raw = b"\x98\x98\x98x"  # 0x98 is undefined in cp1251 → neither utf-8 nor cp1251
    assert apply_brand_map_bytes(raw, compiled) == raw


def test_apply_brand_map_bytes_cp1251():
    """A brand in a cp1251 blob is rewritten; surrounding Cyrillic round-trips."""
    compiled = compile_brand_map([{"pattern": "extyl", "replacement": "acme1", "is_regex": False}])
    raw = "Привет extyl мир".encode("cp1251")  # invalid utf-8 → cp1251 fallback
    out = apply_brand_map_bytes(raw, compiled)
    assert b"extyl" not in out
    decoded = out.decode("cp1251")
    assert "acme1" in decoded
    assert "Привет" in decoded and "мир" in decoded


def test_bad_regex_row_raises():
    """An invalid brand-map regex must fail loudly, not be silently skipped."""
    with pytest.raises(ValueError):
        compile_brand_map([{"pattern": "(unterminated", "replacement": "Z", "is_regex": True}])


def test_load_brand_map_rejects_invalid_regex(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps([{"pattern": "(bad", "replacement": "Z", "is_regex": True}]))
    with pytest.raises(ValueError):
        load_brand_map(p)


def test_filename_delete_and_rename():
    scr = Scrubber(
        SALT,
        brand_map_rows=[{"pattern": "extyl", "replacement": "acme1", "is_regex": False}],
        deny_globs=["**/.env"],
        binary_deny_extensions=["pdf"],
    )
    assert scr.filename(b"src/extyl/foo.py") == b"src/acme1/foo.py"
    assert scr.filename(b"config/.env") == b""
    assert scr.filename(b"docs/report.pdf") == b""
    assert scr.filename(b"src/keep.py") == b"src/keep.py"


# ── load_brand_map ──────────────────────────────────────────────────────────────

def test_load_brand_map_json(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps([{"pattern": "a", "replacement": "b"}]))
    rows = load_brand_map(p)
    assert rows == [{"pattern": "a", "replacement": "b", "is_regex": True, "preserve_case": False}]


def test_load_brand_map_json_rules_wrapper(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"rules": [{"pattern": "a", "replacement": "b", "is_regex": False}]}))
    rows = load_brand_map(p)
    assert rows[0]["is_regex"] is False


def test_load_brand_map_csv(tmp_path):
    p = tmp_path / "m.csv"
    p.write_text("pattern,replacement,is_regex,preserve_case\nfoo,bar,false,true\n,skipme,true,false\n")
    rows = load_brand_map(p)
    assert rows == [{"pattern": "foo", "replacement": "bar", "is_regex": False, "preserve_case": True}]
