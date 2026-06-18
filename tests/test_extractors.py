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


# ── PHP via standalone grammar (ABI-safe capsule path) ───────────────────────

def _php_grammar_available() -> bool:
    try:
        import tree_sitter_php  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _php_grammar_available(), reason="tree-sitter-php not installed")
def test_php_extracted_via_standalone(ts_extractor):
    # extract_zones returns a (possibly empty) list only when a tree-sitter parser
    # was built; it returns None when the grammar is unavailable under
    # on_parse_error=fallback. A non-None result therefore proves the standalone
    # tree-sitter-php grammar loaded via the ABI-safe capsule path.
    code = "<?php\n// secret comment\n$x = 'hello world';\n"
    zones = ts_extractor.extract_zones("test.php", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    assert any("secret comment" in t for t in texts)
    assert any("hello world" in t for t in texts)


# ── ABI mismatch on the language-pack path degrades gracefully (B1) ───────────

def _abi_mismatch_config(on_parse_error: str) -> ExtractorConfig:
    """Config whose single language forces the language-pack fallback path."""
    lang = ExtractorLanguage(
        id="fakelang",
        # No such module → importlib raises ImportError → _try_language_pack path.
        grammar_package="tree-sitter-nonexistent-xyz",
        file_extensions=[".fake"],
        extract_zones=["comment_line"],
    )
    return ExtractorConfig(languages=[lang], on_parse_error=on_parse_error)


def _patch_foreign_language(monkeypatch) -> None:
    """Make the language-pack fallback return a foreign (non tree_sitter.Language)
    object, simulating an ABI-mismatched build whose type is `builtins.Language`."""
    import repo_sanitizer.extractors.treesitter as ts_mod
    monkeypatch.setattr(ts_mod, "_try_language_pack", lambda lang_id: object())


def test_abi_mismatch_fallback_does_not_raise(monkeypatch):
    _patch_foreign_language(monkeypatch)
    extractor = TreeSitterExtractor(_abi_mismatch_config("fallback"))
    # Must NOT raise a TypeError out of extract_zones — degrade to fallback (None).
    zones = extractor.extract_zones("x.fake", "// hi\ncode\n")
    assert zones is None


def test_abi_mismatch_skip_returns_empty(monkeypatch):
    _patch_foreign_language(monkeypatch)
    extractor = TreeSitterExtractor(_abi_mismatch_config("skip"))
    zones = extractor.extract_zones("x.fake", "// hi\ncode\n")
    assert zones == []


def test_abi_mismatch_fail_raises_runtimeerror(monkeypatch):
    _patch_foreign_language(monkeypatch)
    extractor = TreeSitterExtractor(_abi_mismatch_config("fail"))
    # on_parse_error=fail re-raises — and it must be a RuntimeError (the contract
    # extract_zones catches), NOT the raw TypeError from Parser().
    with pytest.raises(RuntimeError, match="ABI mismatch"):
        extractor.extract_zones("x.fake", "// hi\ncode\n")


def test_get_parser_converts_abi_typeerror_to_runtimeerror(monkeypatch):
    """A foreign Language must surface as RuntimeError from _get_parser so
    extract_zones' RuntimeError-only handler honors on_parse_error."""
    _patch_foreign_language(monkeypatch)
    extractor = TreeSitterExtractor(_abi_mismatch_config("fallback"))
    lang = extractor.config.languages[0]
    with pytest.raises(RuntimeError):
        extractor._get_parser(lang)


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


# ── Cyrillic / multibyte zone offsets (byte-vs-char regression) ───────────────
# Zones are returned as CHARACTER offsets; on multibyte UTF-8 a byte-offset zone
# would slice mid-character or overshoot, so the str round-trip would not match.

def test_cyrillic_comment_zone_offsets(ts_extractor):
    code = '# Привет мир секрет\nx = 1\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    # Exact round-trip: with byte offsets this would spill past the comment into
    # the following code line.
    assert any(t.strip() == "# Привет мир секрет" for t in texts)


def test_cyrillic_string_zone_offsets(ts_extractor):
    code = 'value = "Москерам корпорация"\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    texts = [code[z.start:z.end] for z in zones]
    target = next(t for t in texts if "Москерам" in t)
    assert "Москерам корпорация" in target
    assert "\n" not in target  # no byte-offset spillover into the next line


def test_cyrillic_before_ascii_token_alignment(ts_extractor):
    # ASCII token inside a string that begins with Cyrillic: the zone must align
    # so the ASCII token round-trips exactly (proves char, not byte, offsets).
    code = 'x = "Привет admin@corp.com"\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    slices = [code[z.start:z.end] for z in zones]
    target = next(s for s in slices if "admin@corp.com" in s)
    assert "Привет admin@corp.com" in target
    assert "\n" not in target


def test_ascii_offsets_unchanged_fast_path(ts_extractor):
    # Pure ASCII must behave exactly as before (byte == char fast-path).
    code = 'x = "hello world"  # note\n'
    zones = ts_extractor.extract_zones("test.py", code)
    assert zones is not None
    slices = [code[z.start:z.end] for z in zones]
    assert any("hello world" in s for s in slices)
    assert any("note" in s for s in slices)
