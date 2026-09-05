from __future__ import annotations

from repo_sanitizer.detectors.base import ScanTarget
from repo_sanitizer.detectors.legal_id import RuLegalIdDetector
from repo_sanitizer.detectors.requisites import RuRequisitesDetector

INN = "7707083893"          # checksum-valid 10-digit ИНН (anchor)
KPP = "770701001"           # 9 digits, no checksum
ACC = "40702810900000012345"   # 20 digits
LS = "12345678901"          # лицевой счёт, 11 digits


def _vals(findings):
    return sorted(f.matched_value for f in findings)


def test_siblings_next_to_a_valid_inn_are_flagged():
    text = (
        "class Company:\n"
        f"    INN = {INN}\n"
        f'    KPP = "{KPP}"\n'
        f"    settlement = '{ACC}'\n"
        "    name = 'demo'\n"
    )
    f = RuRequisitesDetector().detect(ScanTarget(file_path="fixtures/company.py", content=text))
    assert _vals(f) == sorted([KPP, ACC])
    assert all(x.line in (3, 4) and x.category.value == "PII" and x.severity.value == "HIGH" for x in f)
    # the anchor itself belongs to RuLegalIdDetector, never double-reported here
    assert INN not in _vals(f) and _vals(RuLegalIdDetector().detect(ScanTarget("fixtures/company.py", text))) == [INN]


def test_no_anchor_means_no_findings():
    text = f'kpp = "{KPP}"\naccount = "{ACC}"\nphone = 84951234567\n'
    assert RuRequisitesDetector().detect(ScanTarget(file_path="a.py", content=text)) == []


def test_keyed_runs_anywhere_in_an_anchored_file_and_unkeyed_only_near_the_anchor():
    far = "\n".join(f"x{i} = {i}" for i in range(20))
    text = (
        f"requisites = {{'inn': '{INN}', 'ogrn': '1027700132195'}}\n"     # anchors (line 1)
        + far + "\n"                                                          # 20 filler lines
        f"personal_account = '{LS}'\n"                                       # keyed, far from the anchor → flagged
        f"order_hash = 987654321\n"                                           # 9 digits, unkeyed, far → NOT flagged
        f"'лицевой счёт': '{LS}1'\n"                                          # Cyrillic key → flagged
    )
    vals = _vals(RuRequisitesDetector().detect(ScanTarget(file_path="conftest.py", content=text)))
    assert vals == sorted([LS, LS + "1"])


def test_json_record_and_html_requisites_block():
    js = f'{{"inn": "{INN}", "kpp": "{KPP}", "bik": "044525225", "rs": "{ACC}", "ts": 1700000000}}\n'
    vals = _vals(RuRequisitesDetector().detect(ScanTarget(file_path="org.json", content=js)))
    assert vals == sorted([KPP, "044525225", ACC])          # the unix timestamp is not keyed and not 9/20 digits
    php = f"<p>ИНН {INN}<br>КПП {KPP}<br>Р/с {ACC}</p>\n"
    vals = _vals(RuRequisitesDetector().detect(ScanTarget(file_path="contacts.php", content=php)))
    assert vals == sorted([KPP, ACC])


def test_longer_numbers_are_not_split():
    text = f"INN = {INN}\norder = 7707083893000012345678\n"       # 22 digits: not a run of 8–20
    assert RuRequisitesDetector().detect(ScanTarget(file_path="a.py", content=text)) == []


def test_minified_records_keep_keys_local_to_their_values():
    records = ",".join(
        f'{{"account": "{LS}", "timestamp": 17000000001, "name": "account note"}}'
        for _ in range(256)
    )
    text = f"inn = {INN}\n" + "\n" * 20 + "[" + records + "]"
    findings = RuRequisitesDetector().detect(ScanTarget("records.json", text))
    assert _vals(findings) == [LS] * 256
    assert all(text[f.offset_start:f.offset_end] == LS and f.line == 22 for f in findings)


def test_key_index_does_not_cross_lines_or_accept_intervening_words():
    text = (
        f"inn = {INN}\n" + "\n" * 20
        + f'account\n"{LS}"\n'
        + f'account note: "{LS}"\n'
        + f'account: "{LS}", timestamp: 17000000001\n'
        + f'"лицевой счёт": "{LS}"\n'
    )
    findings = RuRequisitesDetector().detect(ScanTarget("records.txt", text))
    assert _vals(findings) == [LS, LS]
    assert [f.line for f in findings] == [25, 26]
