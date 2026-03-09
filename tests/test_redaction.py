from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, Finding, Severity
from repo_sanitizer.redaction.applier import apply_redactions
from repo_sanitizer.redaction.git_identity import normalize_author, normalize_email
from repo_sanitizer.redaction.replacements import (
    mask_email,
    mask_ip,
    mask_org,
    mask_person,
)


SALT = b"test-salt-unit"


# ── Determinism ────────────────────────────────────────────────────────────────

def test_mask_email_deterministic():
    r1 = mask_email(SALT, "alice@example.com")
    r2 = mask_email(SALT, "alice@example.com")
    assert r1 == r2


def test_mask_person_deterministic():
    r1 = mask_person(SALT, "John Smith")
    r2 = mask_person(SALT, "John Smith")
    assert r1 == r2


def test_mask_org_deterministic():
    r1 = mask_org(SALT, "Acme Corporation")
    r2 = mask_org(SALT, "Acme Corporation")
    assert r1 == r2


def test_mask_ip_deterministic():
    r1 = mask_ip(SALT, "192.168.1.1")
    r2 = mask_ip(SALT, "192.168.1.1")
    assert r1 == r2


def test_different_values_different_hashes():
    r1 = mask_email(SALT, "alice@example.com")
    r2 = mask_email(SALT, "bob@example.com")
    assert r1 != r2


def test_different_salts_different_hashes():
    r1 = mask_email(b"salt1", "alice@example.com")
    r2 = mask_email(b"salt2", "alice@example.com")
    assert r1 != r2


def test_mask_email_format():
    r = mask_email(SALT, "alice@example.com")
    assert r.startswith("REDACTED_EMAIL_")
    assert "@" not in r


def test_mask_person_format():
    r = mask_person(SALT, "John Smith")
    assert r.startswith("ANON_PER_")


def test_mask_org_format():
    r = mask_org(SALT, "Acme Corp")
    assert r.startswith("ANON_ORG_")


def test_mask_ip_format():
    r = mask_ip(SALT, "10.0.0.1")
    assert r.startswith("REDACTED_IP_")
    assert not r[0].isdigit()


# ── Applier: single span ───────────────────────────────────────────────────────

def _make_finding(content: str, value: str, category: Category = Category.PII, severity: Severity = Severity.HIGH) -> Finding:
    start = content.index(value)
    end = start + len(value)
    line = content[:start].count("\n") + 1
    return Finding(
        detector="RegexPIIDetector",
        category=category,
        severity=severity,
        file_path="test.txt",
        line=line,
        offset_start=start,
        offset_end=end,
        matched_value=value,
    )


def test_applier_single_span():
    content = "Contact: alice@example.com here"
    finding = _make_finding(content, "alice@example.com")
    result, manifest = apply_redactions(content, [finding], SALT)
    assert "alice@example.com" not in result
    assert len(manifest) == 1


def test_applier_multiple_spans_reverse_order():
    content = "a@b.com and c@d.com and e@f.com"
    f1 = _make_finding(content, "a@b.com")
    f2 = _make_finding(content, "c@d.com")
    f3 = _make_finding(content, "e@f.com")
    result, manifest = apply_redactions(content, [f1, f2, f3], SALT)
    assert "a@b.com" not in result
    assert "c@d.com" not in result
    assert "e@f.com" not in result
    assert len(manifest) == 3


def test_applier_preserves_surrounding_text():
    content = "Before alice@example.com after"
    finding = _make_finding(content, "alice@example.com")
    result, _ = apply_redactions(content, [finding], SALT)
    assert result.startswith("Before ")
    assert result.endswith(" after")


def test_applier_manifest_fields():
    content = "email: secret@corp.com done"
    finding = _make_finding(content, "secret@corp.com")
    _, manifest = apply_redactions(content, [finding], SALT)
    entry = manifest[0]
    assert entry["original_value"] == "secret@corp.com"
    assert entry["replacement"].startswith("REDACTED_EMAIL_")
    assert "value_hash" in entry
    assert len(entry["value_hash"]) == 12
    assert "ner_label" not in entry


# ── Git identity ───────────────────────────────────────────────────────────────

def test_git_identity_name_deterministic():
    r1 = normalize_author(SALT, "John Doe")
    r2 = normalize_author(SALT, "John Doe")
    assert r1 == r2


def test_git_identity_email_deterministic():
    r1 = normalize_email(SALT, "john@corp.com")
    r2 = normalize_email(SALT, "john@corp.com")
    assert r1 == r2


def test_git_identity_name_format():
    r = normalize_author(SALT, "Jane Smith")
    assert r.startswith("Author_")


def test_git_identity_email_format():
    r = normalize_email(SALT, "jane@corp.com")
    assert r.startswith("author_")
    assert r.endswith("@example.invalid")


def test_git_identity_different_names_differ():
    r1 = normalize_author(SALT, "Alice")
    r2 = normalize_author(SALT, "Bob")
    assert r1 != r2
