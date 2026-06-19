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
    is_bare_domain,
    is_dotted_version,
    is_template,
    looks_low_value_identifier,
    luhn_ok,
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


# ── literal-replace safety (secret/person exact-replace must not clobber code) ──


def test_literal_safety_predicates():
    assert is_dotted_version("4.0.0.0") and is_dotted_version("1.2.3")
    assert not is_dotted_version("4.0.0.0a") and not is_dotted_version("hello")
    assert is_bare_domain("cloud.google.com") and is_bare_domain("getcomposer.org")
    assert not is_bare_domain("Queue") and not is_bare_domain("1.2.3.4")
    # low-value (drop from SECRET literals): short / low-entropy / dict words
    for w in ("com", "acme3", "Queue", "Dashboard", "lodash", "blockchain"):
        assert looks_low_value_identifier(w), w
    # a high-entropy secret-shaped identifier is kept
    assert not looks_low_value_identifier("aB3xK9mP2qLw")


def test_luhn_distinguishes_card_from_numeric_data():
    assert luhn_ok("4111111111111111")          # Visa test card
    assert not luhn_ok("4111111111111112")       # one digit off
    assert not luhn_ok("1234567890123456")       # a fileID / coord run


def test_secret_literal_is_word_boundaried(pii_defs):
    """A standalone identifier literal is masked, but a SUBSTRING of a larger
    identifier is NOT clobbered (Queue must not break QueueDeclare)."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["Queue"])
    out = scr.message(b"ch.QueueDeclare(); q := Queue{}; QueueBind()")
    assert b"QueueDeclare" in out and b"QueueBind" in out  # substrings intact
    assert b"Queue{}" not in out                            # standalone masked
    assert b"REDACTED_" in out


def test_person_literal_is_word_boundaried(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, person_literals=["Dashboard"])
    out = scr.message(b"class DashboardController {} var x = Dashboard;")
    assert b"DashboardController" in out      # substring intact
    assert b"= Dashboard;" not in out         # standalone masked
    assert b"ANON_PER_" in out


def test_credit_card_masked_only_when_luhn_valid(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"valid 4111111111111111 invalid 4111111111111112")
    assert b"4111111111111111" not in out     # real card masked
    assert b"4111111111111112" in out         # luhn-invalid numeric run kept


def test_filter_literals_drops_build_load_bearing():
    from repo_sanitizer.steps.history_rewrite import _filter_literals
    vals = ["4.0.0.0", "cloud.google.com", "Dashboard", "lodash", "aB3xK9mP2qLw"]
    kept = _filter_literals("/nonexistent-path-xyz", vals, secret=True)
    assert "4.0.0.0" not in kept and "cloud.google.com" not in kept
    assert "Dashboard" not in kept and "lodash" not in kept
    assert "aB3xK9mP2qLw" in kept              # a real high-entropy secret survives


def test_filter_literals_person_keeps_short_surnames():
    from repo_sanitizer.steps.history_rewrite import _filter_literals
    kept = _filter_literals("/nonexistent-path-xyz", ["Smith", "Lee", "4.0.0.0"], secret=False)
    assert "Smith" in kept and "Lee" in kept   # real short surnames not dropped
    assert "4.0.0.0" not in kept               # version still dropped


def test_dotted_version_not_masked_as_ip(pii_defs):
    """A 4-part assembly/package version is a valid public IPv4; the version-context
    guard keeps it while a real IP elsewhere is still masked to a doc-range."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, scrub_public_ips=True)
    out = scr.message(b'[assembly: AssemblyVersion("4.0.0.0")] bind 4.0.0.1 here')
    assert b'AssemblyVersion("4.0.0.0")' in out   # version literal preserved
    assert b"4.0.0.1" not in out                  # real IP masked
    assert b"203.0.113." in out


def test_no_bracket_markers_emitted(pii_defs):
    """The old build-breaking '[name:hash]' markers must never appear."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, scrub_public_ips=True, scrub_urls=True)
    out = scr.message(
        b"ip 52.14.226.9 amqp://u:p@host/v jdbc:mysql://h:3306/d apiKey='abcdefghij0123456789'"
    )
    for marker in (b"[ipv4:", b"[ipv6:", b"[db_connection", b"[jdbc_url:",
                   b"[generic_api_key:", b"[secret_url_param:", b"[internal_corp_url:"):
        assert marker not in out, f"build-breaking marker {marker!r} still emitted"
