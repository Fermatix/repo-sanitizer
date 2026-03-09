from __future__ import annotations

from repo_sanitizer.detectors.base import Finding
from repo_sanitizer.redaction.replacements import get_mask


def apply_redactions(
    content: str,
    findings: list[Finding],
    salt: bytes,
) -> tuple[str, list[dict]]:
    """Apply redactions to content based on findings.

    Replaces spans in reverse order to preserve offsets.
    Returns (redacted_content, manifest_entries).
    """
    sorted_findings = sorted(findings, key=lambda f: f.offset_start, reverse=True)

    seen_spans: set[tuple[int, int]] = set()
    manifest = []
    result = content

    for finding in sorted_findings:
        span = (finding.offset_start, finding.offset_end)
        if span in seen_spans:
            continue
        seen_spans.add(span)

        original = result[finding.offset_start : finding.offset_end]
        replacement = _get_replacement(salt, finding)

        result = (
            result[: finding.offset_start]
            + replacement
            + result[finding.offset_end :]
        )

        finding.compute_hash(salt)
        entry: dict = {
            "detector": finding.detector,
            "category": finding.category.value,
            "file_path": finding.file_path,
            "line": finding.line,
            "offset_start": finding.offset_start,
            "offset_end": finding.offset_end,
            "original_value": original,
            "replacement": replacement,
            "value_hash": finding.value_hash,
        }
        if finding.detector == "NERDetector":
            from repo_sanitizer.detectors.base import Category
            entry["ner_label"] = "PER" if finding.category == Category.PII else "ORG"
        manifest.append(entry)

    return result, manifest


def _get_replacement(salt: bytes, finding: Finding) -> str:
    detector = finding.detector
    category = finding.category.value

    if detector == "RegexPIIDetector":
        from repo_sanitizer.rulepack import PIIPattern
        name = _guess_pattern_name(finding)
        return get_mask(salt, finding.matched_value, name, category)

    if detector == "NERDetector":
        if category == "PII":
            return get_mask(salt, finding.matched_value, "PER", category)
        if category == "ORG_NAME":
            return get_mask(salt, finding.matched_value, "ORG", category)

    return get_mask(salt, finding.matched_value, detector, category)


def _guess_pattern_name(finding: Finding) -> str:
    value = finding.matched_value
    if "@" in value and "." in value:
        return "email"
    if value.startswith("+") and value[1:].isdigit():
        return "phone_e164"
    if value.startswith("eyJ"):
        return "jwt"
    if value.startswith("http://") or value.startswith("https://"):
        return "https_url"
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ipv4"
    return finding.category.value
