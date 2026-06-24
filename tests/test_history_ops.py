from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_sanitizer.redaction.history_ops import (
    Scrubber,
    apply_brand_map,
    apply_brand_map_bytes,
    compile_brand_map,
    detect_brand_map_collisions,
    load_brand_map,
)
from repo_sanitizer.rulepack import load_rulepack

RULES_DIR = Path(__file__).parent.parent / "repo_sanitizer" / "rules"
SALT = b"test-salt-12345"


@pytest.fixture(scope="module")
def pii_defs() -> list:
    rp = load_rulepack(RULES_DIR)
    return [(p.name, p.pattern.pattern) for p in rp.pii_patterns]


class _Blob:
    """Minimal stand-in for git_filter_repo's Blob (just a mutable .data)."""

    def __init__(self, data: bytes) -> None:
        self.data = data


# ── non-brand scrubbing (Pass-1) ───────────────────────────────────────────────

def test_message_email_masked_to_invalid_domain(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"Contact john.doe@corp.com for details")
    assert b"@example.invalid" in out
    assert b"corp.com" not in out
    assert b"john.doe" not in out


def test_message_email_scrub_is_idempotent(pii_defs):
    """The @example.invalid mask must not be re-matched (rulepack (?!invalid\\b))."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    once = scr.message(b"mail me at jane@acme.org now")
    twice = scr.message(once)
    assert once == twice


def test_message_phone_masked(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"call +14155550123 tomorrow")
    assert b"+14155550123" not in out
    assert b"+0000000000" in out


def test_message_pii_pattern_masked(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"key AKIAIOSFODNN7EXAMPLE leaked")
    assert b"AKIAIOSFODNN7EXAMPLE" not in out
    # Build-safe: an identifier-safe REDACTED_<NAME>_<hash> token, never a
    # "[name:hash]" bracket marker (which breaks YAML/compose/nginx/JSON).
    assert b"[aws_access_key_id:" not in out
    assert b"REDACTED_AWS_ACCESS_KEY_ID_" in out


def test_secret_literal_scrubbed_in_message_and_blob(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["supersecretvalue"])
    msg = scr.message(b"token=supersecretvalue end")
    assert b"supersecretvalue" not in msg
    assert b"REDACTED_" in msg

    blob = _Blob(b"X = 'supersecretvalue'\n")
    scr.blob(blob)
    assert b"supersecretvalue" not in blob.data
    assert b"REDACTED_" in blob.data


def test_secret_containing_email_fully_masked(pii_defs):
    """A secret literal that embeds an email must be masked as a whole (secrets
    apply before PII), leaving no high-entropy remainder."""
    secret = "abc123ops@corp.com_tail9876"
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=[secret])
    out = scr.message(b"X = " + secret.encode())
    assert secret.encode() not in out
    assert b"abc123" not in out  # the non-email remainder is gone too
    assert b"_tail9876" not in out
    assert b"REDACTED_" in out


def test_person_literal_scrubbed(pii_defs):
    """NER person names collected on the working tree are scrubbed from blobs and
    messages (→ ANON_PER_), closing the filter-repo worktree-reset leak."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, person_literals=["Margaret Thatcher"])
    msg = scr.message(b"Reviewed by Margaret Thatcher last week")
    assert b"Margaret Thatcher" not in msg
    assert b"ANON_PER_" in msg

    blob = _Blob(b"# author: Margaret Thatcher\nx = 1\n")
    scr.blob(blob)
    assert b"Margaret Thatcher" not in blob.data
    assert b"ANON_PER_" in blob.data


def test_person_literal_cp1251(pii_defs):
    """A Cyrillic person name in a cp1251 blob must be scrubbed too (literals are
    matched in both utf-8 and cp1251 byte forms)."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, person_literals=["Иван Петров"])
    blob = _Blob("// автор: Иван Петров\n".encode("cp1251"))
    scr.blob(blob)
    assert "Иван Петров".encode("cp1251") not in blob.data
    assert b"ANON_PER_" in blob.data


def test_blob_skips_binary(pii_defs):
    # GENUINELY binary (a NUL *and* invalid-UTF-8 bytes 0xFF/0x80) → untouched.
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["supersecretvalue"])
    original = b"\x00\x01\xff\xfesupersecretvalue\x80\x81"
    blob = _Blob(original)
    scr.blob(blob)
    assert blob.data == original  # NUL + undecodable bytes → binary, untouched


def test_blob_scrubs_text_with_stray_nul(pii_defs):
    # A TEXT file with a stray NUL (decodes as UTF-8) must STILL be scrubbed —
    # the `notarize.js` leak class (a brand/secret rode along under a NUL because
    # the old "NUL → skip" rule left the whole blob untouched).
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs, secret_literals=["supersecretvalue"])
    original = b"line1\nconst x = 'supersecretvalue';\x00\nline3\n"
    blob = _Blob(original)
    scr.blob(blob)
    assert b"supersecretvalue" not in blob.data
    assert b"REDACTED_" in blob.data
    assert b"\x00" in blob.data  # the stray NUL is preserved; only the secret is masked


def test_config_assignment_secret_value_only(pii_defs):
    # H2: a keyword-assigned config secret gitleaks misses (low entropy / dashes /
    # short) is masked VALUE-ONLY via the grouped-secret route, keeping the YAML
    # key/quotes valid; a non-secret key (DB_PORT) and a placeholder stay intact.
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    blob = _Blob(
        b"DB_PASSWORD: '93V8M0412TJXE'\n"
        b"IQSMS_PASSWORD: '274495'\n"
        b"DB_PORT: '6432'\n"
        b"PUSHER_APP_KEY: 'app-key'\n"
        b"SECRET: '%env(APP_SECRET)%'\n"
    )
    scr.blob(blob)
    out = blob.data
    assert b"93V8M0412TJXE" not in out and b"'274495'" not in out
    assert b"DB_PASSWORD: 'REDACTED_" in out   # key + quotes preserved
    assert b"DB_PORT: '6432'" in out           # non-secret key untouched
    assert b"PUSHER_APP_KEY: 'app-key'" in out  # placeholder untouched
    assert b"%env(APP_SECRET)%" in out          # env-var indirection untouched


def test_cyrillic_pii_regex_redacted_in_history(pii_defs):
    # A Cyrillic regex-PII pattern (fio_ru) must REDACT in the history rewrite, not
    # just be detected: the Scrubber applies the Cyrillic patterns on DECODED text,
    # so the byte-regex Cyrillic-character-class blind spot is gone. utf-8 + cp1251.
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    for enc, token in (("utf-8", "Латышев Сергей Игоревич"), ("cp1251", "Иванов Иван Иванович")):
        blob = _Blob(f"Автор: {token}\n".encode(enc))
        scr.blob(blob)
        assert token.encode(enc) not in blob.data, f"{enc} ФИО survived"
        assert b"REDACTED_FIO_RU_" in blob.data


def test_brand_map_priority_secret_before_brand():
    # H7: a SECRET redaction row with a small priority applies BEFORE a brand
    # substring rule that is a LONGER string than the secret literal — so a brand
    # like `(?i)lkka` can no longer mangle the password `LKKA1`.
    rows = [
        {"pattern": "(?i)lkka", "replacement": "Acme", "is_regex": True, "priority": 100},
        {"pattern": r"(?i)\bLKKA1\b", "replacement": "REDACTED", "is_regex": True, "priority": 0},
    ]
    compiled = compile_brand_map(rows)
    assert compiled[0][1] == "REDACTED"  # priority 0 compiles first
    out = apply_brand_map("the password is LKKA1 today", compiled)
    assert "REDACTED" in out and "Acme" not in out


def test_brands_not_scrubbed_in_pass1(pii_defs):
    """Pass-1 has no brand map → brands stay (detection-only worklist)."""
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    out = scr.message(b"Extyl ships the product")
    assert b"Extyl" in out


def test_author_callbacks(pii_defs):
    scr = Scrubber(SALT, pii_pattern_defs=pii_defs)
    name = scr.author_name(b"John Doe")
    email = scr.author_email(b"john@corp.com")
    assert name.startswith(b"Author_")
    assert email.startswith(b"author_") and email.endswith(b"@example.invalid")
    # deterministic under a fixed salt
    assert scr.author_name(b"John Doe") == name


# ── brand map (Pass-3) ─────────────────────────────────────────────────────────

def test_brand_map_regex_replaces_all_cases():
    scr = Scrubber(
        SALT,
        brand_map_rows=[{"pattern": r"(?i)\bextyl\b", "replacement": "Acme1", "is_regex": True}],
    )
    out = scr.message(b"Extyl and EXTYL and extyl")
    assert b"Extyl" not in out and b"EXTYL" not in out and b"extyl" not in out
    assert out.count(b"Acme1") == 3


def test_brand_map_longest_pattern_first():
    compiled = compile_brand_map(
        [
            {"pattern": "ext", "replacement": "X", "is_regex": False},
            {"pattern": "extyl", "replacement": "Y", "is_regex": False},
        ]
    )
    # 'extyl' (len 5) must run before 'ext' (len 3), else it becomes 'Xyl'
    assert apply_brand_map("extyl", compiled) == "Y"


def test_brand_map_preserve_case():
    compiled = compile_brand_map(
        [{"pattern": "extyl", "replacement": "acme", "is_regex": False, "preserve_case": True}]
    )
    assert apply_brand_map("Extyl EXTYL extyl", compiled) == "Acme ACME acme"


def test_brand_map_replacement_is_literal_not_template():
    # A replacement containing regex backref syntax must stay literal.
    compiled = compile_brand_map(
        [{"pattern": "foo", "replacement": r"A\1B&", "is_regex": False}]
    )
    assert apply_brand_map("foo", compiled) == r"A\1B&"


def test_apply_brand_map_bytes_skips_true_binary():
    compiled = compile_brand_map([{"pattern": "x", "replacement": "y", "is_regex": False}])
    raw = b"\x98\x98\x98x"  # 0x98 is undefined in cp1251 → neither utf-8 nor cp1251
    assert apply_brand_map_bytes(raw, compiled) == raw


def test_apply_brand_map_bytes_cp1251():
    """A brand in a cp1251 blob is rewritten; surrounding Cyrillic round-trips."""
    compiled = compile_brand_map([{"pattern": "extyl", "replacement": "acme1", "is_regex": False}])
    raw = "Привет extyl мир".encode("cp1251")  # invalid utf-8 → cp1251 fallback
    out = apply_brand_map_bytes(raw, compiled)
    assert b"extyl" not in out
    decoded = out.decode("cp1251")
    assert "acme1" in decoded
    assert "Привет" in decoded and "мир" in decoded


def test_bad_regex_row_raises():
    """An invalid brand-map regex must fail loudly, not be silently skipped."""
    with pytest.raises(ValueError):
        compile_brand_map([{"pattern": "(unterminated", "replacement": "Z", "is_regex": True}])


def test_load_brand_map_rejects_invalid_regex(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps([{"pattern": "(bad", "replacement": "Z", "is_regex": True}]))
    with pytest.raises(ValueError):
        load_brand_map(p)


def test_filename_delete_and_rename():
    scr = Scrubber(
        SALT,
        brand_map_rows=[{"pattern": "extyl", "replacement": "acme1", "is_regex": False}],
        deny_globs=["**/.env"],
        binary_deny_extensions=["pdf"],
    )
    assert scr.filename(b"src/extyl/foo.py") == b"src/acme1/foo.py"
    assert scr.filename(b"config/.env") == b""
    assert scr.filename(b"docs/report.pdf") == b""
    assert scr.filename(b"src/keep.py") == b"src/keep.py"


# ── load_brand_map ──────────────────────────────────────────────────────────────

def test_load_brand_map_json(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps([{"pattern": "a", "replacement": "b"}]))
    rows = load_brand_map(p)
    assert rows == [{"pattern": "a", "replacement": "b", "is_regex": True, "preserve_case": False, "priority": 100}]


def test_load_brand_map_json_rules_wrapper(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"rules": [{"pattern": "a", "replacement": "b", "is_regex": False}]}))
    rows = load_brand_map(p)
    assert rows[0]["is_regex"] is False


def test_load_brand_map_csv(tmp_path):
    p = tmp_path / "m.csv"
    p.write_text("pattern,replacement,is_regex,preserve_case\nfoo,bar,false,true\n,skipme,true,false\n")
    rows = load_brand_map(p)
    assert rows == [{"pattern": "foo", "replacement": "bar", "is_regex": False, "preserve_case": True, "priority": 100}]


# ── public-IP-aware scrub (Pass-1; replaces the removed regex `ipv4`) ───────────

@pytest.fixture(scope="module")
def ip_scrubber(pii_defs) -> Scrubber:
    return Scrubber(SALT, pii_pattern_defs=pii_defs, scrub_public_ips=True, keep={"52.14.226.250"})


def test_public_ipv4_scrubbed(ip_scrubber):
    out = ip_scrubber.message(b"host 52.14.226.9 prod")
    assert b"52.14.226.9" not in out
    # Build-safe: a VALID documentation-range IPv4 literal, not a "[ipv4:hash]"
    # marker (which broke docker-compose / k8s / nginx / YAML).
    assert b"[ipv4:" not in out
    assert b"203.0.113." in out


def test_public_ipv6_scrubbed(ip_scrubber):
    out = ip_scrubber.message(b"endpoint 2606:4700:4700::1111 here")
    assert b"2606:4700:4700::1111" not in out
    assert b"[ipv6:" not in out
    assert b"2001:db8::" in out


@pytest.mark.parametrize(
    "ip",
    [b"127.0.0.1", b"192.168.1.10", b"10.0.0.5", b"172.16.0.9", b"100.64.0.1", b"203.0.113.5", b"8.8.8.8"],
)
def test_nonpublic_or_wellknown_ipv4_survives(ip_scrubber, ip):
    out = ip_scrubber.message(b"bind " + ip + b":8080 here")
    assert ip in out, f"{ip!r} (private/loopback/cgnat/doc/well-known-dns) must survive"


def test_kept_public_ip_survives(ip_scrubber):
    out = ip_scrubber.message(b"allow 52.14.226.250 only")
    assert b"52.14.226.250" in out


def test_ula_ipv6_survives(ip_scrubber):
    out = ip_scrubber.message(b"v6 fd00::1 internal")
    assert b"fd00::1" in out


def test_public_ip_scrubbed_in_svg_like_blob(ip_scrubber):
    """codex leak #1 regression: a text blob (SVG / oversized) the inventory-bound
    EndpointDetector scan would skip is STILL covered by the Scrubber IP pass."""
    blob = _Blob(b"<svg><desc>connect 52.14.226.9 prod</desc></svg>")
    ip_scrubber.blob(blob)
    assert b"52.14.226.9" not in blob.data
    assert b"[ipv4:" not in blob.data
    assert b"203.0.113." in blob.data


def test_sln_guid_survives_scrub(ip_scrubber):
    """uuid pattern removed → realistic hex GUIDs are no longer mangled (the .sln
    dotnet-build break); credit_card won't hit hex GUIDs either."""
    out = ip_scrubber.message(b'Project("{9A19103F-16F7-4668-BE54-5B6A7B8C9D0E}") = "App"')
    assert b"9A19103F-16F7-4668-BE54-5B6A7B8C9D0E" in out


def test_plain_url_survives_scrub(ip_scrubber):
    out = ip_scrubber.message(b"feed https://api.nuget.org/v3/index.json end")
    assert b"https://api.nuget.org/v3/index.json" in out


def test_ssh_remote_survives_scrub(ip_scrubber):
    out = ip_scrubber.message(b'"url": "git@github.com:org/repo.git"')
    assert b"git@github.com:org/repo.git" in out


def test_secret_url_param_value_masked(ip_scrubber):
    out = ip_scrubber.message(b"cb https://h/p?token=opaqueSECRET9876543210 done")
    assert b"opaqueSECRET9876543210" not in out


def test_apply_map_mode_does_not_scrub_ips(pii_defs):
    """Pass-3 apply-map (scrub_public_ips default False) stays brand-only — the
    non-brand pass must NOT touch public IPs (Pass-1 already handled them)."""
    scr = Scrubber(SALT, pii_pattern_defs=[], scrub_public_ips=False)
    out = scr.message(b"host 52.14.226.9 prod")
    assert b"52.14.226.9" in out


# ── non-allowlisted URL-host scrub (Pass-1) ─────────────────────────────────────

@pytest.fixture(scope="module")
def url_scrubber(pii_defs) -> Scrubber:
    return Scrubber(SALT, pii_pattern_defs=pii_defs, scrub_urls=True, keep=set())


def test_company_url_host_masked(url_scrubber):
    out = url_scrubber.message(b"BASE = 'https://api.acmevendor.io/v1/users'")
    assert b"acmevendor.io" not in out
    assert b".example.invalid/v1/users" in out  # path kept, structure valid (no [..])


@pytest.mark.parametrize("url", [
    b"https://api.nuget.org/v3/index.json",          # package registry
    b"http://schemas.android.com/apk/res/android",   # xml schema namespace
    b"https://github.com/acmecorp/repo",             # code host (path = brand layer)
    b"https://acme-v02.api.letsencrypt.org/directory",
    b"http://localhost:8080/health",                 # single-label
    b"http://web:3000/api",                          # docker service name
    b"http://192.168.1.10:5432/db",                  # private IP host
])
def test_allowlisted_or_nonidentifying_url_kept(url_scrubber, url):
    out = url_scrubber.message(b"x = '" + url + b"'")
    assert url in out, f"{url!r} must be kept"


def test_public_ip_url_host_masked(url_scrubber):
    out = url_scrubber.message(b"h = 'http://52.14.226.9:9000/x'")
    assert b"52.14.226.9" not in out
    assert b".example.invalid:9000/x" in out


def test_url_host_scrub_idempotent(url_scrubber):
    once = url_scrubber.message(b"u = 'https://api.acmevendor.io/v1'")
    twice = url_scrubber.message(once)
    assert once == twice  # masked host ends in example.invalid → allowlisted, not re-masked


def test_apply_map_mode_does_not_scrub_urls(pii_defs):
    """Pass-3 apply-map (scrub_urls default False) leaves URLs alone."""
    scr = Scrubber(SALT, pii_pattern_defs=[], scrub_urls=False)
    out = scr.message(b"u = 'https://api.acmevendor.io/v1'")
    assert b"acmevendor.io" in out


# ── URL-host edge cases (codex round-2 must-fixes) ──────────────────────────────

def test_multitenant_cloud_subdomain_masked(url_scrubber):
    # a customer-controlled GCS vhost bucket must NOT survive via the googleapis suffix
    out = url_scrubber.message(b"u = 'https://acmecorp.storage.googleapis.com/o'")
    assert b"acmecorp.storage.googleapis.com" not in out
    assert b".example.invalid/o" in out


def test_distinctive_single_label_host_masked(url_scrubber):
    out = url_scrubber.message(b"u = 'http://prod-payments-db:5432/x'")
    assert b"prod-payments-db" not in out  # machine identifier masked


def test_url_userinfo_username_dropped(url_scrubber):
    # a username before @ must not survive even when the host is allowlisted
    out = url_scrubber.message(b"u = 'https://alice@api.nuget.org/x'")
    assert b"alice" not in out
    assert b"api.nuget.org" not in out  # whole authority replaced
    assert b".example.invalid/x" in out


def test_public_ipv6_url_host_masked_no_double_bracket(url_scrubber):
    out = url_scrubber.message(b"u = 'http://[2606:4700:4700::1111]/api'")
    assert b"2606:4700" not in out
    assert b"[[" not in out and b"[ipv6" not in out  # no malformed double-bracket
    assert b".example.invalid/api" in out


def test_doc_ipv6_url_host_kept(url_scrubber):
    out = url_scrubber.message(b"u = 'http://[2001:db8::1]/api'")
    assert b"[2001:db8::1]" in out  # documentation range kept


def test_non_ascii_idn_url_host_masked(url_scrubber):
    # the byte-Scrubber backstop must mask a non-ASCII IDN host, not pass it through
    out = url_scrubber.message("u = 'https://пример.рф/path'".encode("utf-8"))
    assert "пример.рф".encode("utf-8") not in out
    assert b".example.invalid/path" in out


# ── brand-map collision detection (Pass-2 guardrail) ────────────────────────────

def test_detect_brand_map_collisions():
    rows = [
        {"pattern": "extyl", "replacement": "acme1"},
        {"pattern": "Extyl", "replacement": "acme1"},   # 2 DISTINCT patterns → one placeholder
        {"pattern": "globus", "replacement": "acme2"},  # distinct replacement, no collision
    ]
    assert detect_brand_map_collisions(rows) == {"acme1": ["Extyl", "extyl"]}


def test_no_collision_when_replacements_unique():
    rows = [
        {"pattern": "a", "replacement": "acme1"},
        {"pattern": "b", "replacement": "acme2"},
    ]
    assert detect_brand_map_collisions(rows) == {}


def test_collision_ignores_repeated_identical_rows():
    rows = [
        {"pattern": "extyl", "replacement": "acme1"},
        {"pattern": "extyl", "replacement": "acme1"},  # same pattern twice → not a collision
    ]
    assert detect_brand_map_collisions(rows) == {}
