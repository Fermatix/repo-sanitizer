"""Overlapping detector spans on one value: the longest wins, nothing is applied at stale offsets (5d5c9b5c, 2c15624d)."""
from repo_sanitizer.detectors.base import Category, Finding, Severity
from repo_sanitizer.redaction.applier import apply_redactions


def _f(det, cat, a, b, text):
    return Finding(detector=det, category=cat, severity=Severity.HIGH, file_path="settings.py", line=1,
                   offset_start=a, offset_end=b, matched_value=text[a:b])


def test_overlapping_spans_resolve_to_the_longest_and_keep_the_closing_quote():
    text = "CSRF_TRUSTED_ORIGINS = ['http://staging.zorvex-labs.local']\n"
    url_a, url_b = text.index("http://"), text.index("']")
    host_a = text.index("staging"); host_b = url_b
    findings = [
        _f("EndpointDetector", Category.ENDPOINT, host_a, host_b, text),                 # the host
        _f("RegexPIIDetector", Category.ENDPOINT, url_a, url_b, text),                   # internal_corp_url (rulepack 1.5.55: quote excluded)
    ]
    out, manifest = apply_redactions(text, findings, b"salt")
    assert len(manifest) == 1 and manifest[0]["offset_start"] == url_a, "the longest span wins, the other is dropped"
    assert out.count("'") == 2 and out.rstrip().endswith("']"), out
    assert "zorvex" not in out and "invalidCTED" not in out and "REDACTED_URL_" in out


def test_identical_and_disjoint_spans_still_apply():
    text = "a = 'user@corp.example'; b = 'user@corp.example'\n"
    a1 = text.index("user@"); b1 = a1 + len("user@corp.example")
    a2 = text.rindex("user@"); b2 = a2 + len("user@corp.example")
    findings = [_f("RegexPIIDetector", Category.PII, a1, b1, text), _f("RegexPIIDetector", Category.PII, a1, b1, text),
                _f("RegexPIIDetector", Category.PII, a2, b2, text)]
    out, manifest = apply_redactions(text, findings, b"salt")
    assert len(manifest) == 2 and "corp.example" not in out
