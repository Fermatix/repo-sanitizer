from __future__ import annotations

import logging
from typing import Any

from repo_sanitizer.detectors.base import (
    Category,
    Detector,
    Finding,
    ScanTarget,
    Severity,
)
from repo_sanitizer.rulepack import NERConfig

logger = logging.getLogger(__name__)

LABEL_MAP = {
    "PER": (Category.PII, Severity.HIGH),
    "ORG": (Category.ORG_NAME, Severity.MEDIUM),
}

CHUNK_MAX_CHARS = 2000
CHUNK_OVERLAP_LINES = 3


class NERDetector(Detector):
    """Detect person and organization names using a transformer NER model."""

    def __init__(self, config: NERConfig) -> None:
        self.config = config
        self._pipeline = None

    def _ensure_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        try:
            from transformers import pipeline as hf_pipeline
        except ImportError:
            raise RuntimeError(
                "The 'transformers' package is not installed. "
                "Install it with: pip install transformers torch"
            )
        try:
            self._pipeline = hf_pipeline(
                "ner",
                model=self.config.model,
                aggregation_strategy="simple",
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to load NER model '{self.config.model}': {e}. "
                "Ensure the model is downloaded or provide a local path in policies.yaml."
            )
        return self._pipeline

    def detect(self, target: ScanTarget) -> list[Finding]:
        pipe = self._ensure_pipeline()
        findings = []

        if target.is_zoned:
            for zone in target.zones:
                text = target.content[zone.start : zone.end]
                zone_findings = self._detect_text(
                    pipe, text, target.file_path, zone.start
                )
                findings.extend(zone_findings)
        else:
            findings = self._detect_text(pipe, target.content, target.file_path, 0)

        return self._deduplicate(findings)

    def _detect_text(
        self, pipe: Any, text: str, file_path: str, base_offset: int
    ) -> list[Finding]:
        if not text.strip():
            return []
        chunks = self._chunk_text(text)
        findings = []
        for chunk_offset, chunk in chunks:
            try:
                results = pipe(chunk)
            except Exception as e:
                logger.warning("NER inference error: %s", e)
                continue
            for entity in results:
                label = entity.get("entity_group", "")
                if label not in self.config.entity_types:
                    continue
                if label not in LABEL_MAP:
                    continue
                score = entity.get("score", 0)
                if score < self.config.min_score:
                    continue
                word = entity.get("word", "").strip()
                if len(word) < 3:
                    continue
                start = base_offset + chunk_offset + entity["start"]
                end = base_offset + chunk_offset + entity["end"]
                category, severity = LABEL_MAP[label]
                line = text[:entity["start"] + chunk_offset].count("\n") + 1
                findings.append(
                    Finding(
                        detector="NERDetector",
                        category=category,
                        severity=severity,
                        file_path=file_path,
                        line=line,
                        offset_start=start,
                        offset_end=end,
                        matched_value=word,
                    )
                )
        return findings

    def _chunk_text(self, text: str) -> list[tuple[int, str]]:
        if len(text) <= CHUNK_MAX_CHARS:
            return [(0, text)]
        lines = text.split("\n")
        chunks = []
        current_start = 0
        current_lines: list[str] = []
        current_len = 0
        for line in lines:
            line_with_nl = line + "\n"
            if current_len + len(line_with_nl) > CHUNK_MAX_CHARS and current_lines:
                chunk_text = "\n".join(current_lines)
                chunks.append((current_start, chunk_text))
                overlap = current_lines[-CHUNK_OVERLAP_LINES:]
                overlap_len = sum(len(l) + 1 for l in overlap)
                current_start = current_start + current_len - overlap_len
                current_lines = list(overlap)
                current_len = overlap_len
            current_lines.append(line)
            current_len += len(line_with_nl)
        if current_lines:
            chunk_text = "\n".join(current_lines)
            chunks.append((current_start, chunk_text))
        return chunks

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[int, int]] = set()
        result = []
        for f in findings:
            key = (f.offset_start, f.offset_end)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
