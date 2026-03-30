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

CHUNK_OVERLAP_LINES = 3
# GLiNER max token window is 384. Code tokenizes at ~1–1.3 chars/token (subwords,
# special chars, camelCase), so 384 tokens ≈ 300–500 chars. Keep both limits at
# 300 to guarantee no truncation regardless of content.
LINE_MAX_CHARS = 2000
CHUNK_MAX_CHARS = 2000

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
        device = self._resolve_device(self.config.device)
        try:
            import torch
            torch_device = torch.device(device if device != "auto" else "cpu")
            self._gliner = GLiNER.from_pretrained(self.config.model, map_location=torch_device)
            self._gliner = self._gliner.to(torch_device)
            # GLiNER stores its own .device attribute used for tensor placement;
            # .to() moves weights but does NOT update it automatically.
            self._gliner.device = torch_device
        except Exception as e:
            raise RuntimeError(
                f"Failed to load GLiNER model '{self.config.model}' on device '{self.config.device}': {e}."
            )
        logger.info("GLiNER model '%s' loaded on device '%s'", self.config.model, self.config.device)
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
        results = self._infer_batch([chunk])
        return results[0] if results else []

    def _infer_batch(self, chunks: list[str]) -> list[list[dict]]:
        """Run NER inference on multiple chunks in one call. Returns list-of-entity-lists."""
        if not chunks:
            return []
        if self.service_url:
            import httpx
            last_exc: Exception | None = None
            for attempt, delay in enumerate([0, 2, 5, 10]):
                if delay:
                    import time as _time
                    _time.sleep(delay)
                try:
                    resp = httpx.post(
                        f"{self.service_url}/ner",
                        json={"texts": chunks},
                        timeout=3600.0,
                    )
                    if resp.status_code != 200:
                        logger.warning(
                            "NER service returned %d. Response body: %s",
                            resp.status_code,
                            resp.text[:1000],
                        )
                    resp.raise_for_status()
                    return resp.json()["results"]
                except Exception as exc:
                    last_exc = exc
                    logger.warning("NER service attempt %d/3 failed: %s", attempt + 1, exc)
            raise RuntimeError(
                f"NER service at {self.service_url} unreachable after 3 retries: {last_exc}. "
                "Restart the service and re-run."
            )
        if self.config.backend == "gliner":
            return [self._infer_gliner(chunk) for chunk in chunks]
        pipe = self._ensure_pipeline()
        return [pipe(chunk) for chunk in chunks]

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
        chunk_offsets = [co for co, _ in chunks]
        chunk_texts = [c for _, c in chunks]
        try:
            batch_results = self._infer_batch(chunk_texts)
        except Exception as e:
            logger.warning("NER inference error: %s", e)
            return findings
        for chunk_offset, results in zip(chunk_offsets, batch_results):
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

    @staticmethod
    def _split_long_line(line: str, max_chars: int) -> list[str]:
        """Split a line that exceeds *max_chars* on whitespace or hard-cut."""
        if len(line) <= max_chars:
            return [line]
        parts = []
        while len(line) > max_chars:
            # Try to split on the last space before the limit.
            cut = line.rfind(" ", 0, max_chars)
            if cut <= 0:
                cut = max_chars
            parts.append(line[:cut])
            line = line[cut:].lstrip(" ")
        if line:
            parts.append(line)
        return parts

    def _chunk_text(self, text: str) -> list[tuple[int, str]]:
        if len(text) <= CHUNK_MAX_CHARS:
            return [(0, text)]
        # Expand lines that are individually too long for the model token window.
        raw_lines = text.split("\n")
        expanded: list[str] = []
        for line in raw_lines:
            expanded.extend(self._split_long_line(line, LINE_MAX_CHARS))

        chunks = []
        current_start = 0
        current_lines: list[str] = []
        current_len = 0
        for line in expanded:
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
