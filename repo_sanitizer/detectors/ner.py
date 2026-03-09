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
from repo_sanitizer.rulepack import NERConfig

logger = logging.getLogger(__name__)

LABEL_MAP = {
    "PER": (Category.PII, Severity.HIGH),
    "ORG": (Category.ORG_NAME, Severity.MEDIUM),
}

CHUNK_MAX_CHARS = 2000
CHUNK_OVERLAP_LINES = 3

# GLiNER uses descriptive free-form labels instead of short codes
GLINER_LABEL_MAP = {
    "PER": "person name",
    "ORG": "organization name",
}
# Reverse: descriptive label → code
_GLINER_LABEL_REVERSE = {v: k for k, v in GLINER_LABEL_MAP.items()}


class NERDetector(Detector):
    """Detect person and organization names using a transformer NER model.

    In batch mode, pass ``service_url`` (e.g. ``"http://127.0.0.1:8765"``) so
    that the model is shared via a dedicated NER service process instead of
    being loaded into every worker process.
    """

    def __init__(self, config: NERConfig, service_url: Optional[str] = None) -> None:
        self.config = config
        self.service_url = service_url  # if set, use HTTP mode (batch)
        self._pipeline = None
        self._gliner = None

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
        device = self._resolve_device(self.config.device)
        try:
            if device == "auto":
                self._pipeline = hf_pipeline(
                    "ner",
                    model=self.config.model,
                    aggregation_strategy="simple",
                    device_map="auto",
                )
            else:
                self._pipeline = hf_pipeline(
                    "ner",
                    model=self.config.model,
                    aggregation_strategy="simple",
                    device=device,
                )
        except Exception as e:
            raise RuntimeError(
                f"Failed to load NER model '{self.config.model}' on device '{self.config.device}': {e}. "
                "Ensure the model is downloaded or provide a local path in policies.yaml."
            )
        logger.info("NER model '%s' loaded on device '%s'", self.config.model, self.config.device)
        return self._pipeline

    @staticmethod
    def _resolve_device(device: str) -> str:
        """Validate and resolve device string; warn if CUDA requested but unavailable."""
        if device in ("auto",):
            return device
        if device.startswith("cuda"):
            try:
                import torch
                if not torch.cuda.is_available():
                    logger.warning(
                        "CUDA device '%s' requested but torch.cuda.is_available() is False. "
                        "Falling back to CPU.",
                        device,
                    )
                    return "cpu"
            except ImportError:
                logger.warning(
                    "CUDA device '%s' requested but torch is not installed. "
                    "Falling back to CPU.",
                    device,
                )
                return "cpu"
        return device

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings = []

        if target.is_zoned:
            for zone in target.zones:
                text = target.content[zone.start : zone.end]
                zone_findings = self._detect_text(text, target.file_path, zone.start)
                findings.extend(zone_findings)
        else:
            findings = self._detect_text(target.content, target.file_path, 0)

        return self._deduplicate(findings)

    def _ensure_gliner(self) -> Any:
        if self._gliner is not None:
            return self._gliner
        try:
            from gliner import GLiNER
        except ImportError:
            raise RuntimeError(
                "The 'gliner' package is not installed. "
                "Install it with: pip install gliner"
            )
        try:
            self._gliner = GLiNER.from_pretrained(self.config.model)
        except Exception as e:
            raise RuntimeError(
                f"Failed to load GLiNER model '{self.config.model}': {e}."
            )
        logger.info("GLiNER model '%s' loaded", self.config.model)
        return self._gliner

    def _infer_gliner(self, chunk: str) -> list[dict]:
        """Run GLiNER inference. Returns entities in the same format as HF pipeline."""
        model = self._ensure_gliner()
        labels = [GLINER_LABEL_MAP.get(et, et.lower()) for et in self.config.entity_types]
        entities = model.predict_entities(chunk, labels, threshold=self.config.min_score)
        results = []
        for ent in entities:
            code = _GLINER_LABEL_REVERSE.get(ent["label"], ent["label"].upper())
            if code not in LABEL_MAP:
                continue
            results.append({
                "entity_group": code,
                "score": ent["score"],
                "word": ent["text"],
                "start": ent["start"],
                "end": ent["end"],
            })
        return results

    def _infer(self, chunk: str) -> list[dict]:
        """Run NER inference on a single text chunk. Uses HTTP service if configured."""
        if self.service_url:
            try:
                import httpx
                resp = httpx.post(
                    f"{self.service_url}/ner",
                    json={"texts": [chunk]},
                    timeout=30.0,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "NER service returned %d. Response body: %s",
                        resp.status_code,
                        resp.text[:1000],
                    )
                resp.raise_for_status()
                return resp.json()["results"][0]
            except Exception as e:
                logger.warning("NER service call failed: %s", e)
                return []
        if self.config.backend == "gliner":
            return self._infer_gliner(chunk)
        pipe = self._ensure_pipeline()
        return pipe(chunk)

    def _detect_text(
        self, text: str, file_path: str, base_offset: int
    ) -> list[Finding]:
        if not text.strip():
            return []
        # Eagerly load the model before the inference loop so that configuration
        # errors (wrong model name, missing package) propagate to the caller
        # instead of being silently swallowed by the per-chunk try/except below.
        if not self.service_url:
            if self.config.backend == "gliner":
                self._ensure_gliner()
            else:
                self._ensure_pipeline()
        chunks = self._chunk_text(text)
        findings = []
        for chunk_offset, chunk in chunks:
            try:
                results = self._infer(chunk)
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
