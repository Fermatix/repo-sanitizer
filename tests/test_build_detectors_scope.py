from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from repo_sanitizer.detectors.ner import NERDetector
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.scan import build_detectors

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"

# build_detectors constructs SecretsDetector(), which requires gitleaks on PATH.
requires_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


@pytest.fixture(scope="module")
def rulepack():
    return load_rulepack(RULES_DIR)


def _has_ner(detectors) -> bool:
    return any(isinstance(d, NERDetector) for d in detectors)


@requires_gitleaks
def test_ner_scope_off_omits_ner_detector(rulepack):
    detectors = build_detectors(rulepack, ner_scope="off")
    assert not _has_ner(detectors)


@requires_gitleaks
def test_ner_scope_head_includes_ner_detector(rulepack):
    detectors = build_detectors(rulepack, ner_scope="head")
    assert _has_ner(detectors)


@requires_gitleaks
def test_ner_scope_all_includes_ner_detector(rulepack):
    detectors = build_detectors(rulepack, ner_scope="all")
    assert _has_ner(detectors)


@requires_gitleaks
def test_default_scope_includes_ner_detector(rulepack):
    # default is "head"
    assert _has_ner(build_detectors(rulepack))
