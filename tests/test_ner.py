from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, ScanTarget, Severity, Zone
from repo_sanitizer.detectors.ner import NERDetector
from repo_sanitizer.rulepack import NERConfig


def _model_available() -> bool:
    try:
        import transformers  # noqa: F401
        import torch  # noqa: F401
        return True
    except ImportError:
        return False


# Mark all tests as skippable when model/deps unavailable
pytestmark = pytest.mark.skipif(
    not _model_available(),
    reason="NER model not available (requires transformers + torch)",
)


@pytest.fixture
def ner_detector():
    config = NERConfig(
        model="Davlan/bert-base-multilingual-cased-ner-hrl",
        min_score=0.7,
        entity_types=["PER", "ORG"],
    )
    return NERDetector(config)


# ── Person detection ──────────────────────────────────────────────────────────

def test_ner_detects_person_english(ner_detector):
    content = "Fixed by John Smith in the last release."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    per_findings = [f for f in findings if f.category == Category.PII]
    assert per_findings, "Expected PER entity for 'John Smith'"
    assert any("John" in f.matched_value or "Smith" in f.matched_value for f in per_findings)


def test_ner_detects_org_english(ner_detector):
    content = "Report prepared for Acme Corporation by the team."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    org_findings = [f for f in findings if f.category == Category.ORG_NAME]
    assert org_findings, "Expected ORG entity for 'Acme Corporation'"


def test_ner_detects_person_russian(ner_detector):
    content = "Исправлено Иваном Петровым из команды."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    per_findings = [f for f in findings if f.category == Category.PII]
    assert per_findings, "Expected PER entity for Russian name"


def test_ner_person_severity_high(ner_detector):
    content = "Author: Jane Doe"
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    per = [f for f in findings if f.category == Category.PII]
    if per:
        assert per[0].severity == Severity.HIGH


def test_ner_org_severity_medium(ner_detector):
    content = "Sponsored by Google Inc."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    org = [f for f in findings if f.category == Category.ORG_NAME]
    if org:
        assert org[0].severity == Severity.MEDIUM


def test_ner_short_match_ignored(ner_detector):
    """Matches shorter than 3 characters should be ignored."""
    content = "Contact: Jo from AB."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    short = [f for f in findings if len(f.matched_value.strip()) < 3]
    assert not short


def test_ner_span_within_content(ner_detector):
    content = "Fixed by John Smith here."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = ner_detector.detect(target)
    for f in findings:
        assert 0 <= f.offset_start < f.offset_end <= len(content)
        span_text = content[f.offset_start:f.offset_end]
        assert len(span_text.strip()) >= 3


def test_ner_zone_filtering(ner_detector):
    content = "# John Smith wrote this\nx = some_var\n"
    comment_end = content.index("\n")
    zones = [Zone(start=0, end=comment_end)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = ner_detector.detect(target)
    # All findings must be within the zone
    for f in findings:
        assert f.offset_start >= 0
        assert f.offset_end <= comment_end


def test_ner_model_unavailable_raises():
    config = NERConfig(
        model="nonexistent/model-that-does-not-exist",
        min_score=0.7,
        entity_types=["PER", "ORG"],
    )
    detector = NERDetector(config)
    target = ScanTarget(file_path="test.txt", content="John Smith")
    with pytest.raises(RuntimeError, match="model"):
        detector.detect(target)
