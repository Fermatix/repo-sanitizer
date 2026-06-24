from __future__ import annotations

import pytest

from repo_sanitizer.detectors.base import Category, ScanTarget

natasha = pytest.importorskip("natasha")  # skip the whole module if natasha absent

from repo_sanitizer.detectors.ner_natasha import NatashaNERDetector  # noqa: E402


def test_natasha_catches_two_token_name():
    # The patronymic-anchored fio_ru regex CANNOT catch `Имя Фамилия` (no
    # patronymic); CPU NER is exactly the gap-filler.
    det = NatashaNERDetector()
    findings = det.detect(ScanTarget(file_path="x.php", content="Ответственный Иванов Пётр согласовал"))
    assert any(f.matched_value == "Иванов Пётр" for f in findings)
    # emitted as NERDetector/PII so the existing person-literal collection picks it up
    f = findings[0]
    assert f.detector == "NERDetector"
    assert f.category == Category.PII


@pytest.mark.parametrize("text", ["class TaskHandler implements Api", "Город Москва, улица Ленина"])
def test_natasha_no_false_positive_on_code_or_geo(text):
    det = NatashaNERDetector()
    assert not det.detect(ScanTarget(file_path="x.php", content=text))


def test_natasha_respects_keep():
    det = NatashaNERDetector(keep={"иванов пётр"})
    findings = det.detect(ScanTarget(file_path="x.php", content="Ответственный Иванов Пётр"))
    assert not any(f.matched_value == "Иванов Пётр" for f in findings)
