from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import ScanTarget
from repo_sanitizer.detectors.legal_id import RuLegalIdDetector, is_valid_ru_legal_id


@pytest.mark.parametrize("value", [
    "7707083893",        # Sberbank ИНН (10-digit, real checksum)
    "500100732259",      # 12-digit ИНН (valid checksum)
    "1027700132195",     # Sberbank ОГРН (13-digit, valid)
])
def test_valid_legal_ids_detected(value):
    assert is_valid_ru_legal_id(value)
    findings = RuLegalIdDetector().detect(
        ScanTarget(file_path="t.txt", content=f"requisites line\n{value}\nnext")
    )
    assert any(f.matched_value == value for f in findings)


@pytest.mark.parametrize("value", [
    "1718800000000",     # 13-digit unix-ms timestamp (bad ОГРН year field 71 → rejected)
    "1234567890",        # random 10-digit (bad ИНN checksum)
    "0000000000",
    "1234567890123",     # random 13-digit
])
def test_non_legal_ids_not_detected(value):
    assert not is_valid_ru_legal_id(value)
    findings = RuLegalIdDetector().detect(
        ScanTarget(file_path="t.txt", content=f"x = {value}\n")
    )
    assert not findings


def test_digit_run_not_glued_to_longer_number():
    # A valid ИНН embedded in a longer digit run must NOT match (it is not the ID).
    findings = RuLegalIdDetector().detect(
        ScanTarget(file_path="t.txt", content="id = 77070838931234567\n")
    )
    assert not findings


def test_checksum_detector_is_zone_free():
    """A bare int in code (no string/comment zone) and HTML text outside <?php ?> are exactly where the
    audit rounds kept finding valid ИНН by hand — the checksum makes the zone restriction pure lost recall."""
    from repo_sanitizer.detectors.base import Zone
    zoned = ScanTarget(file_path="t.py", content="INN = 7707083893\nx = 1\n", zones=[Zone(0, 0)])   # zoned file, id outside every zone
    assert [f.matched_value for f in RuLegalIdDetector().detect(zoned)] == ["7707083893"]
    html = ScanTarget(file_path="t.php", content="<p>ИНН 1027700132195</p>\n", zones=[])
    assert [f.matched_value for f in RuLegalIdDetector().detect(html)] == ["1027700132195"]
