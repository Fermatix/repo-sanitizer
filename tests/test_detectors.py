from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, Finding, ScanTarget, Severity, Zone
from repo_sanitizer.detectors.dictionary import DictionaryDetector
from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor
from repo_sanitizer.rulepack import load_rulepack


RULES_DIR = __import__("pathlib").Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def rulepack():
    return load_rulepack(RULES_DIR)


@pytest.fixture
def regex_detector(rulepack):
    return RegexPIIDetector(rulepack.pii_patterns)


# ── Email ──────────────────────────────────────────────────────────────────────

def test_regex_email_detected(regex_detector):
    content = "Contact me at john.doe@example.com for details."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    emails = [f for f in findings if "email" in f.detector.lower() or "@" in f.matched_value]
    assert any(f.matched_value == "john.doe@example.com" for f in findings)


def test_regex_email_span_correct(regex_detector):
    content = "Send to alice@corp.com please."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    email_f = next(f for f in findings if "alice@corp.com" in f.matched_value)
    assert content[email_f.offset_start:email_f.offset_end] == "alice@corp.com"


def test_regex_email_line_number(regex_detector):
    content = "line1\nline2\nContact: bob@test.org\nline4"
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    email_f = next(f for f in findings if "bob@test.org" in f.matched_value)
    assert email_f.line == 3


# ── JWT ────────────────────────────────────────────────────────────────────────

def test_regex_jwt_detected(regex_detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f'Authorization: Bearer {jwt}'
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    assert any(f.matched_value == jwt for f in findings)


def test_regex_jwt_severity_critical(regex_detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f"token={jwt}"
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    jwt_findings = [f for f in findings if f.matched_value == jwt]
    assert jwt_findings
    assert jwt_findings[0].severity == Severity.CRITICAL


# ── Zone filtering ─────────────────────────────────────────────────────────────

def test_regex_zone_filtering(regex_detector):
    content = "# comment: admin@corp.com\nsome_var = 'safe'"
    # Only zone covering the comment
    zones = [Zone(start=0, end=26)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    assert any("admin@corp.com" in f.matched_value for f in findings)


def test_regex_outside_zone_ignored(regex_detector):
    content = "# safe comment\nemail = 'admin@corp.com'"
    # Zone covers only the comment, not the assignment
    zones = [Zone(start=0, end=15)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    assert not any("admin@corp.com" in f.matched_value for f in findings)


# ── Phone ──────────────────────────────────────────────────────────────────────

def test_regex_phone_e164(regex_detector):
    content = "Call us at +15551234567 anytime."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    assert any("+15551234567" in f.matched_value for f in findings)


# ── Cyrillic zone gating (byte-vs-char regression) ───────────────────────────
# These build zones with the REAL tree-sitter extractor (byte offsets
# internally, character offsets after the fix) and assert that a finding inside
# a zone that FOLLOWS multibyte content survives _in_zones and round-trips.

@pytest.fixture
def ts_extractor():
    return TreeSitterExtractor(load_rulepack(RULES_DIR).extractor)


def test_regex_email_in_zone_after_cyrillic(regex_detector, ts_extractor):
    # The comment zone starts AFTER `"Привет"`, so a byte-offset zone start
    # exceeds the email's character offset and _in_zones wrongly drops it.
    content = 'x = "Привет"\n# admin@corp.com\n'
    zones = ts_extractor.extract_zones("t.py", content)
    target = ScanTarget(file_path="t.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    matches = [f for f in findings if "admin@corp.com" in f.matched_value]
    assert matches, "email in a comment after Cyrillic must be detected"
    assert content[matches[0].offset_start:matches[0].offset_end] == "admin@corp.com"


def test_dictionary_cyrillic_term_in_zone(ts_extractor):
    # DictionaryDetector had no unit coverage; this also exercises a Cyrillic
    # brand term inside a string zone that follows a Cyrillic comment.
    detector = DictionaryDetector({"orgs": ["Москерам"]})
    content = '# комментарий\nname = "Москерам"\n'
    zones = ts_extractor.extract_zones("t.py", content)
    target = ScanTarget(file_path="t.py", content=content, zones=zones)
    findings = detector.detect(target)
    matches = [f for f in findings if f.matched_value == "Москерам"]
    assert matches, "Cyrillic brand term inside a string zone must be detected"
    assert content[matches[0].offset_start:matches[0].offset_end] == "Москерам"


# ── gitleaks column → char offset (Fix C) ────────────────────────────────────

def test_find_offset_ascii_unchanged():
    from repo_sanitizer.detectors.secrets import _find_offset
    content = "line1\nKEY = abc\n"
    # 1-based line 2, column 7 ('a' of "abc") -> char offset of 'a'
    assert _find_offset(content, 2, 7) == content.index("abc")


def test_find_offset_byte_column_with_cyrillic():
    from repo_sanitizer.detectors.secrets import _find_offset
    # A multibyte char precedes the token on the same line; gitleaks reports a
    # BYTE column. "ключ = " -> 'к','л','ю','ч' are 2 bytes each.
    content = "ключ = SECRET123\n"
    prefix = "ключ = "
    byte_col = len(prefix.encode("utf-8")) + 1  # 1-based byte column of 'S'
    assert _find_offset(content, 1, byte_col) == content.index("SECRET123")
