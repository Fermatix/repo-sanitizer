"""Lightweight CPU Russian-NER backend (Natasha / Slovnet).

The default `hf` / `gliner` NER backends need PyTorch + a ~700 MB transformer and
realistically a GPU — so the whole-repo driver runs `--ner-scope off` and leans
on the Pass-2 agents for person names, which repeatedly miss real ФИО. Natasha is
a pure-numpy CPU pipeline (~50 MB embeddings, ~0.6 s load, sub-millisecond
inference) that, in benchmarking, catches the 2-token `Имя Фамилия` names the
patronymic-anchored `fio_ru` regex CANNOT (it needs a patronymic) — `Иванов Пётр`,
`Мария Смирнова` — with no false positives on code identifiers or geography.

This detector emits findings as ``detector="NERDetector"`` / ``Category.PII`` so
they flow through the EXISTING person-literal collection (``_collect_person_literals``)
and ``ANON_PER_<hash>`` redaction unchanged — only PERSON entities (the high-value,
low-risk class); ORG/LOC are left to the dictionary / Pass-2 brand layer. Selected
via the rulepack ``ner.backend: natasha`` (CPU); gracefully refuses to load if the
package is absent, exactly like the gitleaks / gliner gates.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)

logger = logging.getLogger(__name__)

_MIN_NAME_LEN = 3


class NatashaNERDetector(Detector):
    """Detect Russian PERSON names on CPU via Natasha (no torch, no GPU)."""

    def __init__(self, keep: Optional[set[str]] = None) -> None:
        self.keep = keep or set()
        self._pipeline: Any = None

    def _ensure_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        try:
            from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter
        except ImportError as e:
            raise RuntimeError(
                "The 'natasha' package is not installed (ner.backend: natasha). "
                "Install it with: pip install natasha"
            ) from e
        emb = NewsEmbedding()
        self._pipeline = {
            "Doc": Doc,
            "segmenter": Segmenter(),
            "ner": NewsNERTagger(emb),
        }
        logger.info("Natasha CPU NER pipeline loaded")
        return self._pipeline

    def detect_batch(self, targets: list[ScanTarget]) -> list[Finding]:
        """Loop ``detect`` over targets (Natasha inference is sub-ms, so the
        history-blob ``--ner-scope all`` path needs no special batching)."""
        out: list[Finding] = []
        for t in targets:
            out.extend(self.detect(t))
        return out

    def detect(self, target: ScanTarget) -> list[Finding]:
        if target.is_zoned:
            findings: list[Finding] = []
            for zone in target.zones:
                findings.extend(
                    self._detect_text(target.content[zone.start:zone.end], target, zone.start)
                )
            return findings
        return self._detect_text(target.content, target, 0)

    def _detect_text(self, text: str, target: ScanTarget, base: int) -> list[Finding]:
        if not text.strip():
            return []
        p = self._ensure_pipeline()
        doc = p["Doc"](text)
        doc.segment(p["segmenter"])
        doc.tag_ner(p["ner"])
        findings: list[Finding] = []
        for span in doc.spans:
            if span.type != "PER":
                continue
            value = span.text.strip()
            if len(value) < _MIN_NAME_LEN:
                continue
            if value.lower() in self.keep:
                continue
            start = base + span.start
            end = base + span.stop
            line = target.content[:start].count("\n") + 1
            findings.append(
                Finding(
                    detector="NERDetector",  # reuse → existing PER collection + ANON_PER mask
                    category=Category.PII,
                    severity=Severity.HIGH,
                    file_path=target.file_path,
                    line=line,
                    offset_start=start,
                    offset_end=end,
                    matched_value=value,
                )
            )
        return findings
