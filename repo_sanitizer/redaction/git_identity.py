from __future__ import annotations

from repo_sanitizer.redaction.replacements import mask_author_email, mask_author_name


def normalize_author(salt: bytes, name: str) -> str:
    return mask_author_name(salt, name)


def normalize_email(salt: bytes, email: str) -> str:
    return mask_author_email(salt, email)
