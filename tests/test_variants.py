from __future__ import annotations

import pytest

from repo_sanitizer.variants import expand_term


def test_empty_input_yields_empty_set():
    assert expand_term("") == set()
    assert expand_term("   ") == set()


def test_single_token_includes_itself():
    forms = expand_term("Extyl")
    assert "Extyl" in forms


def test_separator_variants_for_multiword():
    forms = {f.lower() for f in expand_term("Acme Corp")}
    # glued / hyphen / underscore / dot all generated; matcher folds case
    assert {"acmecorp", "acme-corp", "acme_corp", "acme.corp", "acme corp"} <= forms


def test_separator_handles_hyphen_input():
    # `mdm-light` must also yield the glued form `mdmlight` (the real lesson:
    # mdmlight survived a gate that only had mdm-light, and vice-versa).
    forms = {f.lower() for f in expand_term("mdm-light")}
    assert "mdmlight" in forms
    assert "mdm-light" in forms
    assert "mdm_light" in forms


# ── Mojibake (double-encoded cp1251) — regression-locks the transform ─────────

@pytest.mark.parametrize(
    "cyrillic,mojibake",
    [
        ("Яндекс", "РЇРЅРґРµРєСЃ"),
        ("Тинькоф", "РўРёРЅСЊРєРѕС„"),
    ],
)
def test_mojibake_documented_pairs(cyrillic, mojibake):
    assert mojibake in expand_term(cyrillic), (
        f"{cyrillic!r} must expand to its double-encoded-cp1251 form {mojibake!r}"
    )


def test_cyrillic_term_has_mojibake_form():
    # Every Cyrillic-bearing expansion gets a mojibake sibling.
    forms = expand_term("Сбербанк")
    assert any(not f.isascii() and "Р" in f for f in forms)


def test_mojibake_drops_dead_token_for_capital_i():
    # Capital И (U+0418) UTF-8 byte 0x98 is undefined in cp1251 -> U+FFFD. A
    # mojibake form containing the replacement char is a dead token that can
    # never match a real leak, so it must be DROPPED, not emitted.
    forms = expand_term("Иннотех")
    assert not any("�" in f for f in forms), "U+FFFD dead mojibake token must be dropped"
    assert "Иннотех" in forms  # original always preserved


# ── Transliteration backstop guards ──────────────────────────────────────────

@pytest.mark.parametrize("short", ["to", "vk", "in", "on"])
def test_short_terms_get_no_translit(short):
    # Short translit tokens (то/вк/ин/он) substring-match ubiquitous Russian
    # words; the length guard must suppress them.
    forms = {f.lower() for f in expand_term(short)}
    assert not any(not f.isascii() for f in forms), f"{short!r} must not transliterate"


def test_translit_no_mixed_script_garbage():
    # x/w/q are covered, so a Latin term transliterates fully (Линукс, not Линуx).
    forms = expand_term("Linux")
    cyr = [f for f in forms if not f.isascii()]
    assert cyr, "Linux (len>=4) should transliterate"
    assert not any(any("a" <= c.lower() <= "z" for c in f) for f in cyr), "no mixed-script form"


def test_camelcase_input_yields_separator_variants():
    forms = {f.lower() for f in expand_term("AcmeCorp")}
    assert {"acmecorp", "acme-corp", "acme_corp"} <= forms


def test_no_mojibake_for_pure_latin_without_translit_cyrillic():
    # A pure-ASCII term with no separators still round-trips; its only Cyrillic
    # form comes from the translit backstop, which may add a mojibake form — but
    # the original ASCII term is always present and never mangled.
    forms = expand_term("Stripe")
    assert "Stripe" in forms
