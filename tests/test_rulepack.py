from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.rulepack import load_rulepack


RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


def test_load_valid_rulepack():
    rp = load_rulepack(RULES_DIR)
    assert rp.version
    assert len(rp.deny_globs) > 0
    assert len(rp.allow_suffixes) > 0
    assert len(rp.binary_deny_extensions) > 0


def test_rulepack_has_pii_patterns():
    rp = load_rulepack(RULES_DIR)
    assert len(rp.pii_patterns) > 0
    names = [p.name for p in rp.pii_patterns]
    assert "email" in names
    assert "phone_e164" in names


def test_rulepack_has_ner_config():
    rp = load_rulepack(RULES_DIR)
    assert rp.ner.model
    assert 0 < rp.ner.min_score <= 1.0
    assert "PER" in rp.ner.entity_types
    assert "ORG" in rp.ner.entity_types


def test_rulepack_has_extractor_config():
    rp = load_rulepack(RULES_DIR)
    assert len(rp.extractor.languages) >= 3
    ids = [lang.id for lang in rp.extractor.languages]
    assert "python" in ids
    assert "javascript" in ids
    assert "typescript" in ids


def test_missing_version_raises(tmp_path):
    rulepack_dir = tmp_path / "rules"
    rulepack_dir.mkdir()
    (rulepack_dir / "policies.yaml").write_text("deny_globs: []")
    with pytest.raises(FileNotFoundError, match="VERSION"):
        load_rulepack(rulepack_dir)


def test_missing_grammar_package_raises(tmp_path):
    rulepack_dir = tmp_path / "rules"
    rulepack_dir.mkdir()
    (rulepack_dir / "VERSION").write_text("1.0.0")
    (rulepack_dir / "policies.yaml").write_text("deny_globs: []")
    (rulepack_dir / "extractors.yaml").write_text(
        "treesitter:\n"
        "  languages:\n"
        "    - id: python\n"
        "      file_extensions: [.py]\n"
        "      extract_zones: [comment_line]\n"
    )
    with pytest.raises(ValueError, match="grammar_package"):
        load_rulepack(rulepack_dir)


def test_nonexistent_rulepack_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rulepack(tmp_path / "nonexistent")


def test_allow_suffixes_present():
    rp = load_rulepack(RULES_DIR)
    assert ".example" in rp.allow_suffixes
    assert ".sample" in rp.allow_suffixes
    assert ".template" in rp.allow_suffixes
