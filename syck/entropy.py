from __future__ import annotations

import math
import re

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")

_ENTROPY_EXCLUDE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/|"
    r"MDU6[A-Za-z0-9+/=]{10,}"
    r")"
)

_SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(?:"
    r"api[_-]?key|apikey|"
    r"secret|secret[_-]?key|"
    r"password|passwd|pwd|"
    r"token|bearer|"
    r"auth(?:orization)?|credential|"
    r"private[_-]?key|access[_-]?key|"
    r"client[_-]?(?:id|secret)|"
    r"aws|gcp|azure|s3|"
    r"encryption[_-]?key|signing[_-]?key|"
    r"jwt|oauth|"
    r"ssh[_-]?key"
    r")\b"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def likely_secret(value: str, min_len: int = 20, min_entropy: float = 3.5) -> bool:
    candidate = value.strip().strip("'\"`)")
    if len(candidate) < min_len:
        return False
    if candidate.isdigit():
        return False
    char_classes = sum([
        any(ch.islower() for ch in candidate),
        any(ch.isupper() for ch in candidate),
        any(ch.isdigit() for ch in candidate),
        any(ch in "+/=_-@$!%^&*()" for ch in candidate),
    ])
    if char_classes < 3:
        return False
    return shannon_entropy(candidate) >= min_entropy
