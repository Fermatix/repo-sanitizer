from __future__ import annotations

import hmac


def _hash(salt: bytes, value: str, length: int = 12) -> str:
    return hmac.new(salt, value.encode(), "sha256").hexdigest()[:length]


def mask_email(salt: bytes, value: str) -> str:
    return f"REDACTED_EMAIL_{_hash(salt, value)}"


def mask_phone(salt: bytes, value: str) -> str:
    return "+0000000000"


def mask_person(salt: bytes, value: str) -> str:
    return f"ANON_PER_{_hash(salt, value)}"


def mask_org(salt: bytes, value: str) -> str:
    return f"ANON_ORG_{_hash(salt, value)}"


def mask_domain(salt: bytes, value: str) -> str:
    return f"{_hash(salt, value, 8)}.example.invalid"


def mask_ip(salt: bytes, value: str) -> str:
    return f"REDACTED_IP_{_hash(salt, value)}"


def mask_secret(salt: bytes, value: str) -> str:
    return f"REDACTED_{_hash(salt, value)}"


def mask_dictionary(salt: bytes, value: str) -> str:
    return f"TERM_{_hash(salt, value)}"


def mask_endpoint(salt: bytes, value: str) -> str:
    return f"{_hash(salt, value, 8)}.example.invalid"


def mask_author_name(salt: bytes, value: str) -> str:
    return f"Author_{_hash(salt, value)}"


def mask_author_email(salt: bytes, value: str) -> str:
    h = _hash(salt, value)
    return f"author_{h}@example.invalid"


def mask_jwt(salt: bytes, value: str) -> str:
    return f"REDACTED_JWT_{_hash(salt, value)}"


def mask_url(salt: bytes, value: str) -> str:
    return f"REDACTED_URL_{_hash(salt, value)}"


CATEGORY_MASKERS = {
    "email": mask_email,
    "phone": mask_phone,
    "phone_e164": mask_phone,
    "person": mask_person,
    "PER": mask_person,
    "org": mask_org,
    "ORG": mask_org,
    "domain": mask_domain,
    "ip": mask_ip,
    "ipv4": mask_ip,
    "secret": mask_secret,
    "SECRET": mask_secret,
    "dictionary": mask_dictionary,
    "DICTIONARY": mask_dictionary,
    "endpoint": mask_endpoint,
    "ENDPOINT": mask_endpoint,
    "jwt": mask_jwt,
    "https_url": mask_url,
}


def get_mask(salt: bytes, value: str, detector_name: str, category: str) -> str:
    key = detector_name if detector_name in CATEGORY_MASKERS else category
    masker = CATEGORY_MASKERS.get(key)
    if masker:
        return masker(salt, value)
    return f"REDACTED_{_hash(salt, value)}"
