from __future__ import annotations

import json

from repo_sanitizer.batch.worker import _blocking_gate_failures


def _write(p, gates):
    p.write_text(json.dumps({"gates": gates}), encoding="utf-8")
    return p


_CLEAN = {
    "SECRETS": {"passed": True},
    "PII_HIGH": {"passed": True},
    "ENDPOINTS": {"passed": True},
    "FORBIDDEN_FILES": {"passed": True},
    "CONFIGS": {"passed": True},
    # Structural delivery invariants (added with keep-all-branches) — a real
    # result.json always carries them; they block the batch push if red.
    "NO_TAGS": {"passed": True},
    "BRANCHES_PRESERVED": {"passed": True},
}


def test_brand_only_red_is_deliverable(tmp_path):
    """Brand-worklist gates red but all leak gates green → safe to deliver."""
    p = _write(tmp_path / "r.json", {
        **_CLEAN,
        "ORG_NAME": {"passed": False},
        "BRAND_PATH": {"passed": False},
        "BRAND_IDENTIFIER": {"passed": False},
        "PACKAGE_NAMESPACE": {"passed": False},
        "DICTIONARY": {"passed": False},
    })
    assert _blocking_gate_failures(p) == []


def test_secret_red_blocks(tmp_path):
    p = _write(tmp_path / "r.json", {**_CLEAN, "SECRETS": {"passed": False}})
    assert _blocking_gate_failures(p) == ["SECRETS"]


def test_pii_and_endpoint_red_block(tmp_path):
    p = _write(tmp_path / "r.json", {
        **_CLEAN, "PII_HIGH": {"passed": False}, "ENDPOINTS": {"passed": False}
    })
    assert _blocking_gate_failures(p) == ["ENDPOINTS", "PII_HIGH"]


def test_no_tags_red_blocks(tmp_path):
    p = _write(tmp_path / "r.json", {**_CLEAN, "NO_TAGS": {"passed": False}})
    assert _blocking_gate_failures(p) == ["NO_TAGS"]


def test_branches_preserved_red_blocks(tmp_path):
    p = _write(tmp_path / "r.json", {**_CLEAN, "BRANCHES_PRESERVED": {"passed": False}})
    assert _blocking_gate_failures(p) == ["BRANCHES_PRESERVED"]


def test_clean_ref_names_red_is_advisory(tmp_path):
    """A residual identifier in a branch NAME is advisory — keeping all branches
    outranks it, so it must NOT block delivery."""
    p = _write(tmp_path / "r.json", {**_CLEAN, "CLEAN_REF_NAMES": {"passed": False}})
    assert _blocking_gate_failures(p) == []


def test_missing_result_json_fails_closed(tmp_path):
    assert _blocking_gate_failures(tmp_path / "does-not-exist.json")


def test_no_gates_section_fails_closed(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"exit_code": 0}), encoding="utf-8")
    assert _blocking_gate_failures(p)
