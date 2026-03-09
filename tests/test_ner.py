from __future__ import annotations

from unittest.mock import MagicMock, patch

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


# ── GLiNER backend ────────────────────────────────────────────────────────────

def _gliner_available() -> bool:
    try:
        import gliner  # noqa: F401
        return True
    except ImportError:
        return False


def _make_gliner_config(**kwargs) -> NERConfig:
    return NERConfig(backend="gliner", model="urchade/gliner_multi-v2.1", min_score=0.5, **kwargs)


def _mock_gliner_model(entities: list[dict]) -> MagicMock:
    """Return a mock GLiNER model that yields the given entities."""
    model = MagicMock()
    model.predict_entities.return_value = entities
    return model


# Unit tests with mock — do not require gliner installed

def test_gliner_detects_person_mock():
    config = _make_gliner_config()
    detector = NERDetector(config)
    detector._gliner = _mock_gliner_model([
        {"label": "person name", "score": 0.95, "text": "John Smith", "start": 10, "end": 20},
    ])
    content = "Written by John Smith here."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = detector.detect(target)
    per = [f for f in findings if f.category == Category.PII]
    assert per, "Expected PER finding from GLiNER"
    assert per[0].matched_value == "John Smith"
    assert per[0].offset_start == 10
    assert per[0].offset_end == 20


def test_gliner_detects_org_mock():
    config = _make_gliner_config()
    detector = NERDetector(config)
    detector._gliner = _mock_gliner_model([
        {"label": "organization name", "score": 0.88, "text": "Acme Corp", "start": 14, "end": 23},
    ])
    target = ScanTarget(file_path="test.txt", content="Prepared for Acme Corp today.")
    findings = detector.detect(target)
    org = [f for f in findings if f.category == Category.ORG_NAME]
    assert org, "Expected ORG finding from GLiNER"
    assert org[0].matched_value == "Acme Corp"
    assert org[0].severity == Severity.MEDIUM


def test_gliner_unknown_label_ignored():
    """Entities with labels not in LABEL_MAP must be silently dropped."""
    config = _make_gliner_config()
    detector = NERDetector(config)
    detector._gliner = _mock_gliner_model([
        {"label": "location", "score": 0.9, "text": "Moscow", "start": 0, "end": 6},
    ])
    target = ScanTarget(file_path="test.txt", content="Moscow is a city.")
    findings = detector.detect(target)
    assert findings == []


def test_gliner_zone_filtering_mock():
    """GLiNER findings outside zones must be filtered out."""
    config = _make_gliner_config()
    detector = NERDetector(config)
    # Comment zone covers chars 0-22; "John Smith" at 2-12 is inside
    detector._gliner = _mock_gliner_model([
        {"label": "person name", "score": 0.9, "text": "John Smith", "start": 2, "end": 12},
    ])
    content = "# John Smith wrote this\nx = 1\n"
    zone_end = content.index("\n")
    zones = [Zone(start=0, end=zone_end)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = detector.detect(target)
    for f in findings:
        assert f.offset_end <= zone_end


def test_gliner_missing_package_raises():
    config = _make_gliner_config()
    detector = NERDetector(config)
    with patch.dict("sys.modules", {"gliner": None}):
        detector._gliner = None  # force re-init
        with pytest.raises(RuntimeError, match="gliner"):
            detector._ensure_gliner()


# Integration tests — skipped when gliner not installed

@pytest.mark.skipif(not _gliner_available(), reason="gliner not installed")
def test_gliner_detects_person_real():
    detector = NERDetector(_make_gliner_config())
    target = ScanTarget(file_path="test.txt", content="Written by John Smith.")
    findings = detector.detect(target)
    assert any(f.category == Category.PII for f in findings)


@pytest.mark.skipif(not _gliner_available(), reason="gliner not installed")
def test_gliner_detects_org_real():
    detector = NERDetector(_make_gliner_config())
    target = ScanTarget(file_path="test.txt", content="Sponsored by Acme Corporation.")
    findings = detector.detect(target)
    assert any(f.category == Category.ORG_NAME for f in findings)
