from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, Finding, ScanTarget, Severity, Zone
from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
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
