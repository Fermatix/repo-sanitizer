from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.context import RunContext
from repo_sanitizer.detectors.base import Category, Finding, Severity
from repo_sanitizer.rulepack import load_rulepack
from repo_sanitizer.steps.gate import run_gate_check


RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def gate_ctx(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    ctx = RunContext(
        salt=b"test-salt",
        work_dir=tmp_path / "work",
        out_dir=tmp_path / "out",
        artifacts_dir=artifacts,
        rulepack_path=RULES_DIR,
        rulepack=load_rulepack(RULES_DIR),
    )
    return ctx


def _finding(category: Category) -> Finding:
    return Finding(
        detector="BrandStructuralDetector",
        category=category,
        severity=Severity.HIGH,
        file_path="src/ExtylProfile.php",
        line=1,
        offset_start=0,
        offset_end=5,
        matched_value="Extyl",
    )


def test_clean_run_passes_all_gates(gate_ctx):
    result = run_gate_check(gate_ctx)
    assert result["all_passed"] is True
    assert result["exit_code"] == 0


@pytest.mark.parametrize(
    "category,gate",
    [
        (Category.BRAND_IDENTIFIER, "BRAND_IDENTIFIER"),
        (Category.BRAND_PATH, "BRAND_PATH"),
        (Category.PACKAGE_NAMESPACE, "PACKAGE_NAMESPACE"),
        (Category.ORG_NAME, "ORG_NAME"),
    ],
)
def test_brand_findings_fail_their_gate(gate_ctx, category, gate):
    gate_ctx.post_findings = [_finding(category)]
    result = run_gate_check(gate_ctx)
    assert result["gates"][gate]["passed"] is False
    assert result["gates"][gate]["failing_count"] == 1
    assert result["exit_code"] == 1
    # an unrelated gate is unaffected
    assert result["gates"]["SECRETS"]["passed"] is True


def test_brand_gate_enumerates_worklist(gate_ctx):
    gate_ctx.post_findings = [
        _finding(Category.BRAND_IDENTIFIER),
        _finding(Category.BRAND_IDENTIFIER),
        _finding(Category.BRAND_PATH),
    ]
    result = run_gate_check(gate_ctx)
    assert result["gates"]["BRAND_IDENTIFIER"]["failing_count"] == 2
    assert result["gates"]["BRAND_PATH"]["failing_count"] == 1
