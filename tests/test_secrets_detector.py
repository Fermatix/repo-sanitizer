from __future__ import annotations

import shutil

import pytest

from repo_sanitizer.detectors.base import Category, ScanTarget
from repo_sanitizer.detectors.secrets import build_gitleaks_config

requires_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


def test_gitleaks_config_is_valid_toml():
    """A malformed self-mask config makes gitleaks fail to load → detection
    silently disabled. Guard the config is parseable TOML."""
    try:
        import tomllib
    except ModuleNotFoundError:  # py<3.11
        pytest.skip("tomllib unavailable")
    tomllib.loads(build_gitleaks_config(allowlist_masks=True))
    tomllib.loads(build_gitleaks_config(allowlist_masks=False))


@requires_gitleaks
def test_secrets_detector_actually_detects_a_secret():
    """Regression guard: with the --config applied, a real secret is STILL found
    (a broken config previously made detect() silently return [])."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    # A high-entropy generic key reliably flagged by gitleaks (generic-api-key).
    # Deliberately NOT a provider-token shape (Slack/AWS/…) — those trip GitHub
    # push protection when this test source is committed; the AWS EXAMPLE key is
    # also a poor probe (gitleaks allowlists it).
    content = "api_key=Xb7Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk\n"
    findings = det.detect(ScanTarget(file_path="leak.txt", content=content))
    assert any(f.category == Category.SECRET for f in findings), (
        "SecretsDetector must detect a real secret with the allowlist config loaded"
    )


@requires_gitleaks
def test_secrets_detector_allowlists_own_masks():
    """Our 12-hex placeholder masks must be suppressed (so convergence settles)."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    content = "token = REDACTED_0123456789ab\nemail = user_0123456789ab@example.invalid\n"
    findings = det.detect(ScanTarget(file_path="x.txt", content=content))
    flagged = " ".join(f.matched_value for f in findings)
    assert "REDACTED_0123456789ab" not in flagged
    assert "user_0123456789ab@example.invalid" not in flagged


@requires_gitleaks
def test_allowlist_does_not_suppress_real_redacted_prefixed_secret():
    """The allowlist is anchored to EXACTLY 12 hex — a real high-entropy secret
    that merely starts with 'REDACTED_' (non-hex tail) must still be flagged."""
    from repo_sanitizer.detectors.secrets import SecretsDetector

    det = SecretsDetector()
    val = "REDACTED_Kp2Lm9Qr4Ts8Wv3Yz6Ac1Df5Gh0Jk22xZ"  # not 12-hex after prefix
    content = f'api_key = "{val}"\n'
    findings = det.detect(ScanTarget(file_path="x.txt", content=content))
    assert any(f.category == Category.SECRET for f in findings), (
        "anchored allowlist must NOT suppress a real secret that only resembles a mask"
    )
