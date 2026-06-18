from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, Finding, ScanTarget, Severity, Zone
from repo_sanitizer.detectors.brand_structural import (
    BrandMatcher,
    BrandPathDetector,
    BrandStructuralDetector,
)
from repo_sanitizer.detectors.dictionary import DictionaryDetector
from repo_sanitizer.detectors.endpoint import EndpointDetector
from repo_sanitizer.detectors.regex_pii import RegexPIIDetector
from repo_sanitizer.extractors.treesitter import TreeSitterExtractor
from repo_sanitizer.rulepack import Rulepack, load_rulepack
from repo_sanitizer.steps.scan import build_brand_terms


RULES_DIR = __import__("pathlib").Path(__file__).parent.parent / "repo_sanitizer" / "rules"


@pytest.fixture
def rulepack():
    return load_rulepack(RULES_DIR)


@pytest.fixture
def regex_detector(rulepack):
    return RegexPIIDetector(rulepack.pii_patterns)


# ── Email ──────────────────────────────────────────────────────────────────────

def test_regex_email_detected(regex_detector):
    content = "Contact me at john.doe@example.com for details."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    emails = [f for f in findings if "email" in f.detector.lower() or "@" in f.matched_value]
    assert any(f.matched_value == "john.doe@example.com" for f in findings)


def test_regex_email_span_correct(regex_detector):
    content = "Send to alice@corp.com please."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    email_f = next(f for f in findings if "alice@corp.com" in f.matched_value)
    assert content[email_f.offset_start:email_f.offset_end] == "alice@corp.com"


def test_regex_email_line_number(regex_detector):
    content = "line1\nline2\nContact: bob@test.org\nline4"
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    email_f = next(f for f in findings if "bob@test.org" in f.matched_value)
    assert email_f.line == 3


# ── JWT ────────────────────────────────────────────────────────────────────────

def test_regex_jwt_detected(regex_detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f'Authorization: Bearer {jwt}'
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    assert any(f.matched_value == jwt for f in findings)


def test_regex_jwt_severity_critical(regex_detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f"token={jwt}"
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    jwt_findings = [f for f in findings if f.matched_value == jwt]
    assert jwt_findings
    assert jwt_findings[0].severity == Severity.CRITICAL


# ── Zone filtering ─────────────────────────────────────────────────────────────

def test_regex_zone_filtering(regex_detector):
    content = "# comment: admin@corp.com\nsome_var = 'safe'"
    # Only zone covering the comment
    zones = [Zone(start=0, end=26)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    assert any("admin@corp.com" in f.matched_value for f in findings)


def test_regex_outside_zone_ignored(regex_detector):
    content = "# safe comment\nemail = 'admin@corp.com'"
    # Zone covers only the comment, not the assignment
    zones = [Zone(start=0, end=15)]
    target = ScanTarget(file_path="test.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    assert not any("admin@corp.com" in f.matched_value for f in findings)


# ── Phone ──────────────────────────────────────────────────────────────────────

def test_regex_phone_e164(regex_detector):
    content = "Call us at +15551234567 anytime."
    target = ScanTarget(file_path="test.txt", content=content)
    findings = regex_detector.detect(target)
    assert any("+15551234567" in f.matched_value for f in findings)


# ── Pass-1 over-redaction fixes (rulepack pattern tightening) ───────────────────

def _matched(detector, content: str) -> list[str]:
    t = ScanTarget(file_path="t.txt", content=content)
    return [f.matched_value for f in detector.detect(t)]


def test_regex_email_skips_ssh_git_remote(regex_detector):
    # `git@host:path` is a git SSH remote, not an email — must not be masked
    # (else composer/npm git deps break).
    vals = _matched(regex_detector, 'url = git@github.com:org/repo.git')
    assert not any("github.com" in v for v in vals), f"SSH remote matched as email: {vals}"


def test_regex_email_still_matches_real(regex_detector):
    vals = _matched(regex_detector, "ping alice@corp.com today")
    assert "alice@corp.com" in vals


def test_regex_email_idempotent_on_mask(regex_detector):
    # the @example.invalid mask must not be re-matched
    vals = _matched(regex_detector, "user_abc123def456@example.invalid")
    assert not any("example.invalid" in v for v in vals)


def test_regex_phone_ru_skips_hash_digit_run(regex_detector):
    # a digit run inside a hex/base64 hash must not look like a phone (go.sum)
    vals = _matched(regex_detector, "h1:abc84951234567def0011")
    assert not any(v.lstrip().startswith(("8", "+7")) for v in vals), vals


def test_regex_phone_ru_matches_real(regex_detector):
    vals = _matched(regex_detector, "call +7 (495) 123-45-67 now")
    assert any("495" in v for v in vals)


def test_regex_phone_e164_skips_base64_run(regex_detector):
    vals = _matched(regex_detector, "token aGVs+15551234567x")
    assert "+15551234567" not in vals


def test_regex_secret_url_param_matches(regex_detector):
    vals = _matched(regex_detector, "GET https://h/cb?token=opaqueSECRET99 done")
    assert any("token=opaqueSECRET99" in v for v in vals), vals


def test_regex_secret_url_param_skips_plain_url(regex_detector):
    # a plain build URL with no secret param must NOT be masked
    vals = _matched(regex_detector, "feed https://api.nuget.org/v3/index.json end")
    assert not any("nuget.org" in v for v in vals), vals


# ── review-driven fixes (codex + Claude subagent must-fixes) ────────────────────

def test_regex_email_trailing_dot_still_masked(regex_detector):
    # subagent LEAK: a real email at end-of-sentence must still be caught
    vals = _matched(regex_detector, "Maintainer: real.dev@company.com.")
    assert "real.dev@company.com" in vals


def test_regex_email_port_still_masked(regex_detector):
    # email:port (no path slash) is a real email, not an SSH remote → masked
    vals = _matched(regex_detector, "smtp real.dev@company.com:1234 here")
    assert "real.dev@company.com" in vals


def test_regex_email_skips_multilabel_ssh_remote(regex_detector):
    # multi-label SSH host must not partially match (`git@gitlab.example`)
    vals = _matched(regex_detector, "url = git@gitlab.example.com:team/repo.git")
    assert not any("gitlab" in v for v in vals), f"SSH remote matched as email: {vals}"


def test_regex_secret_url_param_matches_aws_presigned(regex_detector):
    # codex must-fix: AWS/GCP presigned-URL credential params
    vals = _matched(regex_detector, "GET https://b.s3.amazonaws.com/k?X-Amz-Signature=abc123&X-Amz-Date=z")
    assert any("X-Amz-Signature=abc123" in v for v in vals), vals
    vals2 = _matched(regex_detector, "GET https://storage.googleapis.com/b/o?X-Goog-Signature=def456")
    assert any("X-Goog-Signature=def456" in v for v in vals2), vals2


def test_regex_ticket_and_issue_shapes_not_masked(regex_detector):
    # jira_ticket (PROJECT-1234) + github_issue_ref (#123) were REMOVED from Pass-1:
    # they are not PII and over-matched domain/standards codes of the same shape.
    # Standards/charset tokens, metallurgical/test domain codes, and bare issue
    # enumerators must ALL pass through untouched.
    for tok in (
        "UTF-8", "SHA-256", "ISO-8601", "RFC-2616", "BASE-64", "HTTP-2",   # standards
        "KCU-70", "KCV-40", "KV-20", "TK-1",                               # domain test codes
    ):
        vals = _matched(regex_detector, f'code "{tok}" here')
        assert tok not in vals, f"{tok} wrongly masked (ticket/issue shapes removed): {vals}"
    # bare issue-ref enumerators (incl. Russian Javadoc) must not be masked
    for txt in ("Значения #1", "see #2 below"):
        vals = _matched(regex_detector, txt)
        assert not any("#" in v for v in vals), vals


def test_regex_ticket_key_is_pass2_job_not_pass1_pii(regex_detector):
    # A real JIRA PROJECT key names the internal project (brand-adjacent) and is the
    # Pass-2 brand map's responsibility (Option A), not a Pass-1 PII rewrite.
    vals = _matched(regex_detector, "fixes PROJ-1234 and ABC-42")
    assert "PROJ-1234" not in vals and "ABC-42" not in vals


# ── Cyrillic zone gating (byte-vs-char regression) ───────────────────────────
# These build zones with the REAL tree-sitter extractor (byte offsets
# internally, character offsets after the fix) and assert that a finding inside
# a zone that FOLLOWS multibyte content survives _in_zones and round-trips.

@pytest.fixture
def ts_extractor():
    return TreeSitterExtractor(load_rulepack(RULES_DIR).extractor)


def test_regex_email_in_zone_after_cyrillic(regex_detector, ts_extractor):
    # The comment zone starts AFTER `"Привет"`, so a byte-offset zone start
    # exceeds the email's character offset and _in_zones wrongly drops it.
    content = 'x = "Привет"\n# admin@corp.com\n'
    zones = ts_extractor.extract_zones("t.py", content)
    target = ScanTarget(file_path="t.py", content=content, zones=zones)
    findings = regex_detector.detect(target)
    matches = [f for f in findings if "admin@corp.com" in f.matched_value]
    assert matches, "email in a comment after Cyrillic must be detected"
    assert content[matches[0].offset_start:matches[0].offset_end] == "admin@corp.com"


def test_dictionary_cyrillic_term_in_zone(ts_extractor):
    # DictionaryDetector had no unit coverage; this also exercises a Cyrillic
    # brand term inside a string zone that follows a Cyrillic comment.
    detector = DictionaryDetector({"orgs": ["Москерам"]})
    content = '# комментарий\nname = "Москерам"\n'
    zones = ts_extractor.extract_zones("t.py", content)
    target = ScanTarget(file_path="t.py", content=content, zones=zones)
    findings = detector.detect(target)
    matches = [f for f in findings if f.matched_value == "Москерам"]
    assert matches, "Cyrillic brand term inside a string zone must be detected"
    assert content[matches[0].offset_start:matches[0].offset_end] == "Москерам"


def test_endpoint_domain_word_not_matched_on_code_identifier(ts_extractor):
    # Regression for the zone-aware history scan: a bare domains.txt word (`exchange`)
    # must NOT flag the Java code identifier `restTemplate.exchange` (a non-zone code
    # position) — only domains inside string/comment zones. Without zones this match
    # was rewritten across all history, breaking the delivered HEAD build.
    from repo_sanitizer.detectors.endpoint import EndpointDetector

    detector = EndpointDetector(["exchange"], keep=set())
    content = (
        "class C {\n"
        "  void m() {\n"
        "    var r = restTemplate.exchange(uri);\n"  # code identifier — must NOT match
        '    var s = "host.exchange";\n'              # inside a string zone — MUST match
        "  }\n"
        "}\n"
    )
    zones = ts_extractor.extract_zones("C.java", content)
    target = ScanTarget(file_path="C.java", content=content, zones=zones)
    vals = [f.matched_value for f in detector.detect(target)]
    assert not any("restTemplate.exchange" in v for v in vals), vals
    assert any("host.exchange" in v for v in vals), vals


# ── gitleaks column → char offset (Fix C) ────────────────────────────────────

def test_find_offset_ascii_unchanged():
    from repo_sanitizer.detectors.secrets import _find_offset
    content = "line1\nKEY = abc\n"
    # 1-based line 2, column 7 ('a' of "abc") -> char offset of 'a'
    assert _find_offset(content, 2, 7) == content.index("abc")


def test_find_offset_byte_column_with_cyrillic():
    from repo_sanitizer.detectors.secrets import _find_offset
    # A multibyte char precedes the token on the same line; gitleaks reports a
    # BYTE column. "ключ = " -> 'к','л','ю','ч' are 2 bytes each.
    content = "ключ = SECRET123\n"
    prefix = "ключ = "
    byte_col = len(prefix.encode("utf-8")) + 1  # 1-based byte column of 'S'
    assert _find_offset(content, 1, byte_col) == content.index("SECRET123")


# ── Keep-list / allowlist (Change 1) ─────────────────────────────────────────

def test_dictionary_keep_suppresses_term():
    content = 'name = "Yandex"\n'
    target = ScanTarget(file_path="t.txt", content=content)
    assert DictionaryDetector({"orgs": ["Yandex"]}).detect(target), "control: flagged without keep"
    kept = DictionaryDetector({"orgs": ["Yandex"]}, keep={"yandex"}).detect(target)
    assert not kept, "a kept term must not be flagged"


def test_ner_keep_org_precise():
    # No model needed — exercise the keep decision directly.
    from repo_sanitizer.detectors.ner import NERDetector
    from repo_sanitizer.rulepack import NERConfig
    det = NERDetector(NERConfig(), keep={"yandex", "google", "apple"})
    # kept: bare brand, brand + unambiguous legal-form suffix
    assert det._is_kept_org("yandex")
    assert det._is_kept_org("google llc")
    assert det._is_kept_org("yandex inc")
    assert det._is_kept_org("google corp")
    # NOT kept: a distinct org that shares one token with a kept brand — incl.
    # a meaningful noun ("bank"/"cloud") that is NOT a pure legal form
    assert not det._is_kept_org("apple bank")
    assert not det._is_kept_org("yandex cloud")
    assert not det._is_kept_org("apple logistics llc")
    assert not det._is_kept_org("big apple corp")
    assert not det._is_kept_org("acme google llc")
    assert not det._is_kept_org("ооо рога и копыта")


def test_endpoint_keep_suppresses_domain():
    content = "host = acme.internal\n"
    target = ScanTarget(file_path="t.txt", content=content)
    assert EndpointDetector().detect(target), "control: .internal domain flagged"
    kept = EndpointDetector(keep={"acme.internal"}).detect(target)
    assert not any(f.matched_value == "acme.internal" for f in kept)


def test_endpoint_keep_suppresses_subdomain():
    content = "host = api.acme.internal\n"
    findings = EndpointDetector(keep={"acme.internal"}).detect(
        ScanTarget(file_path="t.txt", content=content)
    )
    assert not any("acme.internal" in f.matched_value for f in findings)


# ── Public vs private IP (Change 2) ──────────────────────────────────────────

def test_endpoint_flags_public_ip():
    content = "API = http://52.14.226.9/v1\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    ips = [f for f in findings if f.matched_value == "52.14.226.9"]
    assert ips, "a routable public IP must be flagged"
    assert ips[0].severity == Severity.HIGH


@pytest.mark.parametrize("ip", ["192.168.1.100", "10.0.0.1", "172.16.5.4", "127.0.0.1"])
def test_endpoint_keeps_private_ip(ip):
    content = f"host = {ip}\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    assert not any(f.matched_value == ip for f in findings), f"{ip} (private) must be kept"


@pytest.mark.parametrize("ip", ["192.0.2.5", "198.51.100.7", "203.0.113.9", "8.8.8.8", "1.1.1.1"])
def test_endpoint_keeps_doc_and_wellknown_ip(ip):
    content = f"host = {ip}\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    assert not any(f.matched_value == ip for f in findings), f"{ip} (doc/well-known) must be kept"


@pytest.mark.parametrize("ip", ["100.64.0.1", "100.127.255.254"])
def test_endpoint_keeps_cgnat_ip(ip):
    # RFC6598 shared address space is not globally routable — must be kept.
    content = f"host = {ip}\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    assert not any(f.matched_value == ip for f in findings), f"{ip} (CGNAT) must be kept"


@pytest.mark.parametrize(
    "text",
    ["app version 1.2.3.4.5 here", "OID 1.3.6.1.4.1.311 x", "build 12.34.56.78.90"],
)
def test_endpoint_ignores_version_strings_and_oids(text):
    # The leading quad of a longer dotted-numeric run must NOT be taken for an IP.
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=text))
    assert not findings, f"version string / OID must not flag an IP: {text!r}"


def test_endpoint_flags_public_ipv6():
    content = "dns = 2606:4700:4700::1111\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    assert any(f.matched_value == "2606:4700:4700::1111" for f in findings)


@pytest.mark.parametrize("ip", ["::1", "fe80::1", "2001:db8::1", "fc00::1"])
def test_endpoint_keeps_nonglobal_ipv6(ip):
    content = f"addr = {ip}\n"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.txt", content=content))
    assert not any(f.matched_value == ip for f in findings), f"{ip} (non-global v6) must be kept"


def test_endpoint_flags_company_url_host():
    content = "BASE = 'https://api.acmevendor.io/v1/users'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    hosts = [f.matched_value for f in findings]
    assert "api.acmevendor.io" in hosts, "non-allowlisted URL host must be flagged (the host only)"


@pytest.mark.parametrize("url", [
    "https://api.nuget.org/v3/index.json",
    "http://schemas.android.com/apk/res/android",
    "https://github.com/acmecorp/repo",
    "http://localhost:8080/health",
    "http://web:3000/api",
    "http://192.168.1.10/db",
])
def test_endpoint_keeps_allowlisted_or_nonidentifying_url(url):
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=f"x='{url}'"))
    assert not findings, f"{url} (universal infra / non-identifying) must not be flagged"


def test_endpoint_url_host_in_keep_kept():
    content = "u = 'https://api.acmevendor.io/v1'"
    findings = EndpointDetector(keep={"acmevendor.io"}).detect(
        ScanTarget(file_path="t.py", content=content)
    )
    assert not findings, "a kept domain used as a URL host must not be flagged"


def test_endpoint_flags_multitenant_cloud_subdomain():
    # customer GCS vhost bucket must be flagged (not kept via googleapis suffix)
    content = "u = 'https://acmecorp.storage.googleapis.com/o'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert any("acmecorp.storage.googleapis.com" in f.matched_value for f in findings)


def test_endpoint_keeps_deep_vendor_infra_subdomain():
    # a legitimate multi-label vendor infra host must NOT be flagged
    content = "u = 'https://acme-v02.api.letsencrypt.org/directory'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert not findings, "vendor-controlled deep subdomain must be kept"


def test_endpoint_flags_url_userinfo():
    content = "u = 'https://alice@api.nuget.org/x'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert any("alice@api.nuget.org" in f.matched_value for f in findings), (
        "userinfo (username) before an allowlisted host must be flagged"
    )


def test_endpoint_flags_distinctive_single_label_url_host():
    content = "u = 'http://prod-payments-db:5432/x'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert any("prod-payments-db" in f.matched_value for f in findings)


def test_endpoint_flags_userinfo_on_ip_host_no_duplicate():
    # userinfo on an IP-literal URL host: the username must be flagged (not lost
    # to the IP-skip), as ONE finding spanning userinfo+host (the bare-IP finding
    # is dropped by the containment dedup — no overlapping spans).
    content = "u = 'https://alice@52.14.226.9/x'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert len(findings) == 1, f"expected one merged finding, got {[f.matched_value for f in findings]}"
    assert findings[0].matched_value == "alice@52.14.226.9"


def test_endpoint_flags_userinfo_on_private_ip_host():
    content = "u = 'https://alice@192.168.1.10/x'"
    findings = EndpointDetector().detect(ScanTarget(file_path="t.py", content=content))
    assert any("alice@192.168.1.10" in f.matched_value for f in findings), (
        "userinfo must be flagged even when the host is a (kept) private IP"
    )


def test_endpoint_keeps_ip_in_keep_set():
    content = "host = 52.14.226.9\n"
    findings = EndpointDetector(keep={"52.14.226.9"}).detect(
        ScanTarget(file_path="t.txt", content=content)
    )
    assert not findings


# ── Domains split off the brand dictionary (Change 3) ────────────────────────

def test_build_brand_terms_excludes_domains_and_keep():
    rp = Rulepack(
        path=RULES_DIR,
        version="test",
        dictionaries={
            "orgs": ["Extyl"],
            "domains": ["mail", "jira"],
            "keep": ["Yandex"],
        },
    )
    terms, keep = build_brand_terms(rp)
    lowered = {t.lower() for t in terms}
    assert "extyl" in lowered
    assert "mail" not in lowered and "jira" not in lowered, "domains must not be brand terms"
    assert "yandex" not in lowered, "keep terms must not be brand terms"
    # keep is variant-expanded, so its Cyrillic translit is also exempt
    assert "yandex" in keep
    assert "яндекс" in keep, "keep set must be variant-expanded (Cyrillic form)"


def test_build_brand_terms_variant_expands_brands():
    rp = Rulepack(
        path=RULES_DIR,
        version="test",
        dictionaries={"orgs": ["mdm-light"]},
    )
    terms, _ = build_brand_terms(rp)
    lowered = {t.lower() for t in terms}
    assert {"mdm-light", "mdmlight", "mdm_light"} <= lowered, "brand terms must be variant-expanded"


# ── Brand-in-path (Change 4a) ────────────────────────────────────────────────

class _Item:
    def __init__(self, path):
        self.path = path


def test_brand_path_detects_dir_and_file():
    matcher = BrandMatcher(["extyl"], set())
    det = BrandPathDetector(matcher)
    inv = [_Item("src/extyl/ExtylProfile.php"), _Item("README.md")]
    findings = det.detect_inventory(inv)
    cats = {f.category for f in findings}
    assert cats == {Category.BRAND_PATH}
    vals = {f.matched_value.lower() for f in findings}
    assert "extyl" in vals
    # offsets index into the path string and round-trip exactly
    for f in findings:
        assert f.file_path[f.offset_start : f.offset_end] == f.matched_value


def test_brand_path_dedups_repeated_dir():
    matcher = BrandMatcher(["extyl"], set())
    det = BrandPathDetector(matcher)
    inv = [_Item("src/extyl/A.php"), _Item("src/extyl/B.php"), _Item("src/extyl/C.php")]
    findings = det.detect_inventory(inv)
    # the `extyl` directory must be reported once, not once per file
    assert sum(1 for f in findings if f.matched_value.lower() == "extyl") == 1


# ── Brand-in-identifier / package (Change 4b) ────────────────────────────────

@pytest.fixture
def struct_extractor(rulepack):
    return TreeSitterExtractor(rulepack.extractor)


def test_brand_identifier_in_python_code(struct_extractor):
    # Python grammar is a hard dependency, so this never needs the language pack.
    content = (
        "import extyl.util\n"
        "from extyl.models import ExtylModel\n"
        'note = "contact extyl support"  # see extyl.com\n'
        "class ExtylProfile(Base):\n"
        "    extyl_client = ExtylModel()\n"
    )
    zones = struct_extractor.extract_zones("m.py", content)
    pkg = struct_extractor.extract_identifier_zones("m.py", content)
    assert pkg is not None
    det = BrandStructuralDetector(BrandMatcher(["extyl"], set()))
    findings = det.detect("m.py", content, zones, pkg)
    cats = {f.category for f in findings}
    assert Category.PACKAGE_NAMESPACE in cats, "import statements → PACKAGE_NAMESPACE"
    assert Category.BRAND_IDENTIFIER in cats, "ExtylProfile class → BRAND_IDENTIFIER"
    # brand inside the string literal / comment is DictionaryDetector's job, not here
    lines = {f.line for f in findings if f.category == Category.BRAND_IDENTIFIER}
    assert 3 not in lines, "string/comment match must be excluded from structural pass"


def test_dictionary_catches_string_brand_excluded_by_structural(struct_extractor):
    # Compensating coverage: the structural pass EXCLUDES the string/comment
    # brand precisely because DictionaryDetector is expected to catch it. Prove
    # the brand is covered by exactly one pass and never dropped between them.
    content = 'note = "contact extyl support"\n'
    zones = struct_extractor.extract_zones("m.py", content)
    dict_hits = DictionaryDetector({"orgs": ["extyl"]}).detect(
        ScanTarget(file_path="m.py", content=content, zones=zones)
    )
    assert any(f.matched_value.lower() == "extyl" for f in dict_hits), (
        "brand in a string literal must be caught by DictionaryDetector"
    )
    struct = BrandStructuralDetector(BrandMatcher(["extyl"], set())).detect(
        "m.py", content, zones, struct_extractor.extract_identifier_zones("m.py", content)
    )
    assert not struct, "the same string-literal brand must NOT also be a structural finding"


def test_brand_identifier_keep_suppresses(struct_extractor):
    content = "class YandexClient(Base):\n    pass\n"
    zones = struct_extractor.extract_zones("m.py", content)
    pkg = struct_extractor.extract_identifier_zones("m.py", content)
    det = BrandStructuralDetector(BrandMatcher(["yandex"], keep={"yandex"}))
    assert not det.detect("m.py", content, zones, pkg)


def _language_pack_has(lang_id: str) -> bool:
    try:
        from tree_sitter_language_pack import get_language
        get_language(lang_id)
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _language_pack_has("java"),
    reason="requires tree-sitter-language-pack (java grammar)",
)
def test_brand_package_in_java(struct_extractor):
    content = (
        "package ru.extyl.app;\n"
        "import ru.extyl.util.Helper;\n"
        "public class ExtylProfile {\n"
        "    private int extylClient = 0;\n"
        "}\n"
    )
    zones = struct_extractor.extract_zones("Foo.java", content)
    pkg = struct_extractor.extract_identifier_zones("Foo.java", content)
    assert pkg, "java package/import declarations must be located"
    det = BrandStructuralDetector(BrandMatcher(["extyl"], set()))
    findings = det.detect("Foo.java", content, zones, pkg)
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f.line)
    assert Category.PACKAGE_NAMESPACE in by_cat, "package ru.extyl + import → PACKAGE_NAMESPACE"
    assert Category.BRAND_IDENTIFIER in by_cat, "ExtylProfile / extylClient → BRAND_IDENTIFIER"


@pytest.mark.skipif(
    not _language_pack_has("php"),
    reason="requires tree-sitter-language-pack (php grammar)",
)
def test_brand_package_in_php(struct_extractor):
    # Locks the php node-type strings (namespace_definition / namespace_use_declaration).
    content = (
        "<?php\n"
        "namespace App\\Extyl\\Service;\n"
        "use App\\Extyl\\Model\\ExtylModel;\n"
        "class ExtylProfile extends Base {}\n"
    )
    zones = struct_extractor.extract_zones("Foo.php", content)
    pkg = struct_extractor.extract_identifier_zones("Foo.php", content)
    assert pkg, "php namespace/use declarations must be located"
    findings = BrandStructuralDetector(BrandMatcher(["extyl"], set())).detect(
        "Foo.php", content, zones, pkg
    )
    cats = {f.category for f in findings}
    assert Category.PACKAGE_NAMESPACE in cats
    assert Category.BRAND_IDENTIFIER in cats


def test_build_history_detectors_parity():
    # History blob detectors must mirror the working-tree build: keep-list applied
    # and domains split off the brand DictionaryDetector.
    from repo_sanitizer.steps.history_blob_scan import build_history_detectors
    rp = Rulepack(
        path=RULES_DIR, version="test",
        dictionaries={"orgs": ["Extyl"], "domains": ["jira"], "keep": ["Yandex"]},
    )
    det = next(
        d for d in build_history_detectors(rp) if type(d).__name__ == "DictionaryDetector"
    )
    content = "Extyl and jira and Yandex"
    hits = {f.matched_value.lower() for f in det.detect(ScanTarget(file_path="t.txt", content=content))}
    assert "extyl" in hits, "brand still flagged in history"
    assert "jira" not in hits, "domains split off the history brand dictionary"
    assert "yandex" not in hits, "keep-list applied in history"
