"""A gitleaks generic hit whose value is source code is not a secret literal (5d5c9b5c: three identifiers were stamped over)."""
import shutil

import pytest

from repo_sanitizer.detectors.base import ScanTarget
from repo_sanitizer.detectors.secrets import SecretsDetector, looks_like_code_expression


@pytest.mark.parametrize("value,following", [
    ("settings.WEBDEV_SDK_API_KEY", ","), ("os.environ.get", "("), ("cfg.get", "("), ("config.secrets.mqtt_password", ""),
    ("get_password_from_vault", "("), ("SECRETS", "["),
])
def test_code_expressions_are_not_secrets(value, following):
    assert looks_like_code_expression(value, following)


@pytest.mark.parametrize("value,following", [
    ("Zx9!kq2#Lm8$Pw4%", "'"), ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "'"),
    ("supersecretpassword", "'"), ("AKIAIOSFODNN7EXAMPLE", '"'), ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", ""),
    ("django-insecure-abcde!f#g$h%i^j&k*l(m)n", "'"), ("get_password_from_vault", "'"),
])
def test_credential_shaped_values_stay_secrets(value, following):
    assert not looks_like_code_expression(value, following)


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks binary needed to construct the detector")
def test_build_findings_drops_the_code_expression_but_keeps_the_literal():
    text = "api_key = settings.WEBDEV_SDK_API_KEY\nMQTT_PASSWORD = 'Zx9!kq2#Lm8$Pw4%'\n"
    det = SecretsDetector()
    items = []
    for secret in ("settings.WEBDEV_SDK_API_KEY", "Zx9!kq2#Lm8$Pw4%"):
        line = 1 if secret.startswith("settings") else 2
        col = text.splitlines()[line - 1].index(secret) + 1
        items.append({"Secret": secret, "StartLine": line, "EndLine": line, "StartColumn": col, "EndColumn": col + len(secret) - 1})
    out = det._build_findings(ScanTarget(file_path="settings.py", content=text), items)
    assert [f.matched_value for f in out] == ["Zx9!kq2#Lm8$Pw4%"]
