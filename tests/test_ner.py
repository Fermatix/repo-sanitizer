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


# ── detect_batch ─────────────────────────────────────────────────────────────

def test_detect_batch_returns_findings_for_all_targets():
    """detect_batch flattens results from multiple targets."""
    config = NERConfig(model="irrelevant", min_score=0.5, entity_types=["PER", "ORG"])
    detector = NERDetector(config)
    # Simulate service_url mode so no model is loaded
    detector.service_url = "http://mock"

    targets = [
        ScanTarget(file_path="a.txt", content="Written by John Smith."),
        ScanTarget(file_path="b.txt", content="Approved by Jane Doe."),
    ]

    fake_responses = [
        [{"entity_group": "PER", "score": 0.9, "word": "John Smith", "start": 11, "end": 21}],
        [{"entity_group": "PER", "score": 0.9, "word": "Jane Doe",   "start": 12, "end": 20}],
    ]
    with patch.object(detector, "_infer_batch", return_value=fake_responses) as mock_infer:
        findings = detector.detect_batch(targets)

    assert len(findings) == 2
    assert findings[0].file_path == "a.txt"
    assert findings[1].file_path == "b.txt"
    mock_infer.assert_called_once()


def test_detect_batch_deduplicates_per_target():
    """Overlapping chunks from the same target produce one finding per span."""
    config = NERConfig(model="irrelevant", min_score=0.5, entity_types=["PER"])
    detector = NERDetector(config)
    detector.service_url = "http://mock"

    content = "By John Smith here."
    targets = [ScanTarget(file_path="f.txt", content=content)]

    # Two identical entities (as if from overlapping chunks)
    duplicate_response = [
        [
            {"entity_group": "PER", "score": 0.9, "word": "John Smith", "start": 3, "end": 13},
            {"entity_group": "PER", "score": 0.9, "word": "John Smith", "start": 3, "end": 13},
        ]
    ]
    with patch.object(detector, "_infer_batch", return_value=duplicate_response):
        findings = detector.detect_batch(targets)

    assert len(findings) == 1


def test_detect_batch_empty_targets_returns_empty():
    config = NERConfig(model="irrelevant", min_score=0.5, entity_types=["PER"])
    detector = NERDetector(config)
    detector.service_url = "http://mock"
    assert detector.detect_batch([]) == []


def test_detect_batch_respects_keep_list():
    """Entities whose word is on the keep-list are not emitted."""
    config = NERConfig(model="irrelevant", min_score=0.5, entity_types=["ORG"])
    detector = NERDetector(config, keep={"acme"})
    detector.service_url = "http://mock"

    targets = [ScanTarget(file_path="x.txt", content="Acme Corp did it.")]
    fake = [[{"entity_group": "ORG", "score": 0.9, "word": "Acme", "start": 0, "end": 4}]]
    with patch.object(detector, "_infer_batch", return_value=fake):
        findings = detector.detect_batch(targets)

    assert findings == []


def test_detect_batch_zoned_targets():
    """Zones are respected: only zone text is sent, offsets are absolute."""
    config = NERConfig(model="irrelevant", min_score=0.5, entity_types=["PER"])
    detector = NERDetector(config)
    detector.service_url = "http://mock"

    content = "code(); // John Smith fixed this\nmore code"
    zone_start = content.index("//")
    zone_end = content.index("\n")
    targets = [ScanTarget(file_path="z.py", content=content, zones=[Zone(start=zone_start, end=zone_end)])]

    # Offset inside zone text ("John Smith" starts at index 3 within the zone slice)
    zone_text = content[zone_start:zone_end]
    js_local_start = zone_text.index("John")
    fake = [[{"entity_group": "PER", "score": 0.9, "word": "John Smith",
              "start": js_local_start, "end": js_local_start + 10}]]
    with patch.object(detector, "_infer_batch", return_value=fake):
        findings = detector.detect_batch(targets)

    assert len(findings) == 1
    # offset_start must be absolute in the full content
    assert findings[0].offset_start == zone_start + js_local_start


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
