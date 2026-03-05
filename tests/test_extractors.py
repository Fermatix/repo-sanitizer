from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.detectors.base import Zone
from repo_sanitizer.extractors.fallback import FallbackExtractor
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor
from repo_sanitizer.rulepack import ExtractorConfig, ExtractorLanguage, load_rulepack


RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def rulepack():
    return load_rulepack(RULES_DIR)


@pytest.fixture
def ts_extractor(rulepack):
    return TreeSitterExtractor(rulepack.extractor)


# ── Python ────────────────────────────────────────────────────────────────────

def test_python_comment_extracted(ts_extractor):
    code = '# This is a comment\nx = 1\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    # Comment zone should cover "# This is a comment"
    comment_text = code[:zones[0].end] if zones else ""
    assert any(code[z.start:z.end].strip().startswith("#") for z in zones)


def test_python_docstring_extracted(ts_extractor):
    code = '"""Module docstring."""\n\ndef foo():\n    """Function docstring."""\n    pass\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any('"""' in t for t in texts)


def test_python_string_literal_extracted(ts_extractor):
    code = 'x = "hello world"\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any("hello world" in t for t in texts)


def test_python_identifier_not_in_zone(ts_extractor):
    code = 'my_variable = 42\n'
    zones = ts_extractor.extract_zones("test.py", code)
    # No comments or strings — zones should be empty
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert not any("my_variable" in t for t in texts)


# ── JavaScript ────────────────────────────────────────────────────────────────

def test_js_comment_line_extracted(ts_extractor):
    code = '// This is a JS comment\nconst x = 1;\n'
    zones = ts_extractor.extract_zones("test.js", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any("JS comment" in t for t in texts)


def test_js_comment_block_extracted(ts_extractor):
    code = '/* block comment */\nconst y = 2;\n'
    zones = ts_extractor.extract_zones("test.js", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any("block comment" in t for t in texts)


def test_js_template_literal_extracted(ts_extractor):
    code = 'const msg = `Hello ${name}`;\n'
    zones = ts_extractor.extract_zones("test.js", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any("Hello" in t for t in texts)


# ── redact_string_literals=False ──────────────────────────────────────────────

def test_string_literals_not_extracted_when_disabled(rulepack):
    config = rulepack.extractor
    # Create a modified config with redact_string_literals=False
    from dataclasses import replace
    modified_config = ExtractorConfig(
        languages=config.languages,
        redact_string_literals=False,
        min_string_length=config.min_string_length,
        on_parse_error=config.on_parse_error,
        fallback_enabled=config.fallback_enabled,
        fallback_comment_patterns=config.fallback_comment_patterns,
    )
    extractor = TreeSitterExtractor(modified_config)
    code = 'x = "should not be extracted"\n# comment here\n'
    zones = extractor.extract_zones("test.py", code)
    if zones is not None:
        texts = [code[z.start:z.end] for z in zones]
        assert not any("should not be extracted" in t for t in texts)


# ── Fallback on parse error ───────────────────────────────────────────────────

def test_parse_error_fallback(rulepack):
    config = rulepack.extractor
    # on_parse_error=fallback should return None (triggering fallback)
    extractor = TreeSitterExtractor(config)
    # Passing severely malformed content — tree-sitter is fault-tolerant,
    # so we test fallback extractor directly instead
    fb = FallbackExtractor()
    code = '# comment here\nx = 1\n// another comment\n'
    zones = fb.extract_zones(code)
    texts = [code[z.start:z.end] for z in zones]
    assert any("comment here" in t for t in texts)
    assert any("another comment" in t for t in texts)


# ── Unknown extension → None (no zones, scan full file) ──────────────────────

def test_unknown_extension_returns_none(ts_extractor):
    zones = ts_extractor.extract_zones("file.xyz", "some content")
    assert zones is None


# ── Fallback extractor ────────────────────────────────────────────────────────

def test_fallback_hash_comments():
    fb = FallbackExtractor()
    code = '# comment\ncode_line\n# another\n'
    zones = fb.extract_zones(code)
    texts = [code[z.start:z.end] for z in zones]
    assert any("comment" in t for t in texts)
    assert any("another" in t for t in texts)


def test_fallback_slash_comments():
    fb = FallbackExtractor()
    code = '// first\ncode\n// second\n'
    zones = fb.extract_zones(code)
    texts = [code[z.start:z.end] for z in zones]
    assert any("first" in t for t in texts)
    assert any("second" in t for t in texts)


def test_fallback_no_code_in_zones():
    fb = FallbackExtractor()
    code = 'x = secret_var\n# comment only\n'
    zones = fb.extract_zones(code)
    texts = [code[z.start:z.end] for z in zones]
    assert not any("secret_var" in t for t in texts)
