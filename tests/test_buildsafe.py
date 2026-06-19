"""Build-safety tests: redaction placeholders must stay syntactically inert in
their landing context (the dominant ship-blocking defect found auditing delivered
batches — 18/27 repos were build-broken by a placeholder spliced into syntax it
didn't fit)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from repo_sanitizer.buildsafe import (
    config_parse_regressions,
    contains_mask,
    doc_ipv4,
    doc_ipv6,
    is_template,
    parse_status,
)
from repo_sanitizer.redaction.history_ops import Scrubber
from repo_sanitizer.rulepack import load_rulepack

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
SALT = b"buildsafe-salt"


@pytest.fixture(scope="module")
def pii_defs() -> list:
    rp = load_rulepack(RULES_DIR)
    return [(p.name, p.pattern.pattern) for p in rp.pii_patterns]


# ── is_template ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("v", [
    "amqp://%s:%s@%s:%s/%s",                 # go fmt.Sprintf
    "jdbc:postgresql://{host}:{port}/{db}",  # str.format
    "postgres://${USER}:${PASS}@${HOST}/db", # env interpolation
    "https://app/reset?token={{$token}}",    # blade / mustache
    "redis://#{host}:6379",                  # ruby / kotlin
    "http://<host>/api",                     # angle placeholder
])
def test_is_template_positive(v):
    assert is_template(v)


@pytest.mark.parametrize("v", [
    "amqp://guest:guest@rabbit:5672/",
    "postgres://admin:pw@db.acme.io:5432/app",
    "https://api.acme.io/v1/users",
])
def test_is_template_negative(v):
    assert not is_template(v)


# ── value-kind-preserving placeholders ──────────────────────────────────────────


def test_doc_ipv4_valid_deterministic_and_nonpublic():
    a = doc_ipv4(SALT, b"52.14.226.9")
    assert a == doc_ipv4(SALT, b"52.14.226.9")  # deterministic
    ip = ipaddress.ip_address(a.decode())
    assert ip in ipaddress.ip_network("203.0.113.0/24")
    assert not ip.is_global  # a re-scan never re-flags it


def test_doc_ipv6_valid():
    v = ipaddress.ip_address(doc_ipv6(SALT, b"2606:4700::1").decode())
    assert v in ipaddress.ip_network("2001:db8::/32")


def test_contains_mask():
    assert contains_mask('apiKey = "REDACTED_0123456789ab"')
    assert contains_mask("postgres://abcd1234.example.invalid:5432/db")
    assert contains_mask("user_0123456789ab@example.invalid")
    assert not contains_mask("postgres://admin:pw@db.acme.io/app")
    assert not contains_mask("just some text")


# ── parse_status / regression detection (the PARSEABLE_CONFIGS gate primitive) ──


def test_parse_status_and_regressions(tmp_path):
    (tmp_path / "ok.yaml").write_text("a: 1\nb: 2\n")
    (tmp_path / "data.json").write_text('{"x": 1}')
    (tmp_path / "proj.csproj").write_text("<Project><PropertyGroup/></Project>")
    pre = parse_status(tmp_path)
    assert pre["ok.yaml"] is True and pre["data.json"] is True and pre["proj.csproj"] is True

    # A redaction that breaks the YAML (unclosed flow seq) + the JSON.
    (tmp_path / "ok.yaml").write_text("a: [1, 2\n")
    (tmp_path / "data.json").write_text('{"x": }')
    post = parse_status(tmp_path)
    reg = config_parse_regressions(pre, post)
    assert "ok.yaml" in reg and "data.json" in reg
    assert "proj.csproj" not in reg  # untouched file is not a regression


def test_already_broken_config_is_not_a_regression(tmp_path):
    (tmp_path / "broken.json").write_text("{not json")
    pre = parse_status(tmp_path)
    assert pre["broken.json"] is False
    post = parse_status(tmp_path)            # still broken, unchanged
    assert config_parse_regressions(pre, post) == []  # only valid->invalid counts


# ── Scrubber: structure-preserving, build-safe replacements ─────────────────────


def test_format_string_template_is_left_untouched(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b'addr := fmt.Sprintf("amqp://%s:%s@%s:%s/%s", u, p, h, port, path)')
    assert b"amqp://%s:%s@%s:%s/%s" in out  # the printf args are not orphaned


def test_connection_string_is_host_masked_and_stays_valid(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b'DSN = "postgresql://admin:secret@prod-db.acme.io:5432/app"')
    assert b"admin:secret" not in out          # credentials dropped
    assert b"prod-db.acme.io" not in out       # identifying host masked
    assert b"postgresql://" in out             # scheme + structure kept
    assert b".example.invalid:5432/app" in out  # still a valid connection string
    assert scr.message(out) == out             # idempotent (no double-mangle)


def test_generic_api_key_masks_value_only(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b'static apiKey = "abcdef0123456789ABCDEF0123";')
    assert b"abcdef0123456789ABCDEF0123" not in out
    assert b'apiKey = "REDACTED_' in out       # keyword + opening quote intact
    assert b'";' in out                        # closing quote + statement intact


def test_secret_url_param_masks_value_only_and_skips_templates(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"GET /reset?token=SECRETabc123VALUE&x=1 HTTP/1.1")
    assert b"SECRETabc123VALUE" not in out
    assert b"?token=REDACTED_" in out          # "?name=" prefix kept, value masked
    templ = scr.message(b'url = "/reset?token={{$token}}"')
    assert b"{{$token}}" in templ              # templated param left alone


def test_generic_host_in_connection_string_is_kept(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    assert b"redis://localhost:6379/0" in scr.message(b"redis://localhost:6379/0")


def test_no_bracket_markers_emitted(pii_defs):
    """The old build-breaking '[name:hash]' markers must never appear."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, scrub_public_ips=True, scrub_urls=True)
    out = scr.message(
        b"ip 52.14.226.9 amqp://u:p@host/v jdbc:mysql://h:3306/d apiKey='abcdefghij0123456789'"
    )
    for marker in (b"[ipv4:", b"[ipv6:", b"[db_connection", b"[jdbc_url:",
                   b"[generic_api_key:", b"[secret_url_param:", b"[internal_corp_url:"):
        assert marker not in out, f"build-breaking marker {marker!r} still emitted"
