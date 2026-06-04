from __future__ import annotations

import base64
import gzip
import re
import zlib
from pathlib import Path
from typing import Callable

from syck.entropy import shannon_entropy
from syck.finding import Finding
from syck.rules import _RULE_RANK

_BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}(?!\w)")
_HEX_CANDIDATE_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_URL_ENCODED_RE = re.compile(r"%([0-9a-fA-F]{2})")
_BASE64_MIN_LEN = 32
_HEX_MIN_LEN = 20

MAX_RECURSION_DEPTH = 4


def _try_gzip_decompress(data: bytes) -> bytes | None:
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data)
    except Exception:
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except Exception:
            pass
    return None


def decode_file_content(raw_bytes: bytes) -> str | None:
    decompressed = _try_gzip_decompress(raw_bytes)
    if decompressed is None:
        return None
    try:
        return decompressed.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return decompressed.decode("latin-1", errors="replace")


def _scan_decoded(decoded_text: str, path: str | Path, lineno: int,
                  source_tag: str, rules: list, min_rank: int,
                  add_fn: Callable) -> None:
    for rule in rules:
        if _RULE_RANK.get(rule.name, 99) > min_rank:
            continue
        for m in rule.pattern.finditer(decoded_text):
            secret = m.group(0)
            add_fn(Finding(
                file=str(path), line=lineno, column=0,
                rule=f"{source_tag}_{rule.name}",
                severity=rule.severity,
                secret=secret,
                context=f"{source_tag} decoded: {decoded_text[:200]}",
                entropy=shannon_entropy(secret),
            ))


def _try_decode_base64(text: str) -> list[str]:
    results: list[str] = []
    for m in _BASE64_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        if len(raw) < _BASE64_MIN_LEN:
            continue
        try:
            decoded = base64.b64decode(raw)
        except Exception:
            continue
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\n\r\t")
        if printable < len(decoded_text) // 2:
            continue
        results.append(decoded_text)
    return results


def _try_decode_hex(text: str) -> list[str]:
    results: list[str] = []
    for m in _HEX_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        if len(raw) < _HEX_MIN_LEN:
            continue
        has_upper = any(ch.isupper() for ch in raw)
        has_lower = any(ch.islower() for ch in raw)
        if has_upper and has_lower:
            continue
        try:
            decoded = bytes.fromhex(raw)
        except Exception:
            continue
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\n\r\t")
        if printable < len(decoded_text) // 2:
            continue
        if decoded_text.strip().lower().strip("x") in ("", "hex"):
            continue
        results.append(decoded_text)
    return results


def _try_decode_unicode_escapes(text: str) -> list[str]:
    if "\\u" not in text:
        return []
    decoded = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return [decoded] if decoded != text else []


def _try_decode_url_encoded(text: str) -> list[str]:
    if "%" not in text:
        return []
    decoded = _URL_ENCODED_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return [decoded] if decoded != text else []


_DECODERS = [
    ("unicode", _try_decode_unicode_escapes),
    ("url", _try_decode_url_encoded),
    ("base64", _try_decode_base64),
    ("hex", _try_decode_hex),
]


def recursive_decode_and_rescan(
    line: str,
    path: str | Path,
    lineno: int,
    rules: list,
    min_rank: int,
    add_fn: Callable,
    depth: int = 0,
    max_depth: int = MAX_RECURSION_DEPTH,
) -> None:
    if depth >= max_depth:
        return
    for source_tag, decoder_fn in _DECODERS:
        for decoded_text in decoder_fn(line):
            _scan_decoded(decoded_text, path, lineno, source_tag, rules, min_rank, add_fn)
            recursive_decode_and_rescan(
                decoded_text, path, lineno, rules, min_rank, add_fn,
                depth + 1, max_depth,
            )


def recursive_decode_content(
    content: str,
    path: str | Path,
    rules: list,
    min_rank: int,
    add_fn: Callable,
    depth: int = 0,
    max_depth: int = MAX_RECURSION_DEPTH,
) -> None:
    if depth >= max_depth:
        return
    for lineno, line in enumerate(content.splitlines(), start=1):
        recursive_decode_and_rescan(
            line, path, lineno, rules, min_rank, add_fn, depth, max_depth,
        )
