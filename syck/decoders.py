from __future__ import annotations

import base64
from pathlib import Path

from syck.entropy import shannon_entropy
from syck.finding import Finding
from syck.rules import RULES, _RULE_RANK

_UNICODE_ESCAPE_RE = __import__("re").compile(r"\\u([0-9a-fA-F]{4})")
_URL_ENCODED_RE = __import__("re").compile(r"%([0-9a-fA-F]{2})")

_BASE64_CANDIDATE_RE = __import__("re").compile(r"\b[A-Za-z0-9+/]{32,}={0,2}(?!\w)")
_BASE64_MIN_LEN = 32


def _decode_and_rescan(line: str, path: str | Path, lineno: int,
                       rules: list, min_rank: int,
                       add_fn) -> None:
    for match in _BASE64_CANDIDATE_RE.finditer(line):
        raw = match.group(0)
        if len(raw) < _BASE64_MIN_LEN:
            continue
        try:
            decoded_bytes = base64.b64decode(raw)
        except Exception:
            continue
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\n\r\t")
        if printable < len(decoded_text) // 2:
            continue
        for rule in rules:
            if _RULE_RANK.get(rule.name, 99) > min_rank:
                continue
            for m in rule.pattern.finditer(decoded_text):
                secret = m.group(0)
                add_fn(Finding(
                    file=str(path),
                    line=lineno,
                    rule=f"base64_{rule.name}",
                    severity=rule.severity,
                    secret=secret,
                    context=f"base64 decoded: {decoded_text[:200]}",
                    entropy=shannon_entropy(secret),
                ))


_HEX_CANDIDATE_RE = __import__("re").compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_HEX_MIN_BYTES = 10


def _decode_hex_and_rescan(line: str, path: str | Path, lineno: int,
                           rules: list, min_rank: int,
                           add_fn) -> None:
    for match in _HEX_CANDIDATE_RE.finditer(line):
        raw = match.group(0)
        if len(raw) < _HEX_MIN_BYTES * 2:
            continue
        has_upper = any(ch.isupper() for ch in raw)
        has_lower = any(ch.islower() for ch in raw)
        if has_upper and has_lower:
            continue
        try:
            decoded_bytes = bytes.fromhex(raw)
        except Exception:
            continue
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\n\r\t")
        if printable < len(decoded_text) // 2:
            continue
        if decoded_text.strip().lower().strip("x") in ("", "hex"):
            continue
        for rule in rules:
            if _RULE_RANK.get(rule.name, 99) > min_rank:
                continue
            for m in rule.pattern.finditer(decoded_text):
                secret = m.group(0)
                add_fn(Finding(
                    file=str(path),
                    line=lineno,
                    rule=f"hex_{rule.name}",
                    severity=rule.severity,
                    secret=secret,
                    context=f"hex decoded: {decoded_text[:200]}",
                    entropy=shannon_entropy(secret),
                ))


def _decode_unicode_escapes(line: str, path: str | Path, lineno: int,
                            rules: list, min_rank: int,
                            add_fn) -> None:
    if "\\u" not in line:
        return
    def _replace_escape(m):
        return chr(int(m.group(1), 16))
    decoded = _UNICODE_ESCAPE_RE.sub(_replace_escape, line)
    if decoded == line:
        return
    for rule in rules:
        if _RULE_RANK.get(rule.name, 99) > min_rank:
            continue
        for m in rule.pattern.finditer(decoded):
            secret = m.group(0)
            add_fn(Finding(
                file=str(path),
                line=lineno,
                rule=f"unicode_{rule.name}",
                severity=rule.severity,
                secret=secret,
                context=f"unicode decoded: {decoded[:200]}",
                entropy=shannon_entropy(secret),
            ))


def _decode_url_encoded(line: str, path: str | Path, lineno: int,
                        rules: list, min_rank: int,
                        add_fn) -> None:
    if "%" not in line:
        return
    def _replace_pct(m):
        return chr(int(m.group(1), 16))
    decoded = _URL_ENCODED_RE.sub(_replace_pct, line)
    if decoded == line:
        return
    for rule in rules:
        if _RULE_RANK.get(rule.name, 99) > min_rank:
            continue
        for m in rule.pattern.finditer(decoded):
            secret = m.group(0)
            add_fn(Finding(
                file=str(path),
                line=lineno,
                rule=f"url_{rule.name}",
                severity=rule.severity,
                secret=secret,
                context=f"url decoded: {decoded[:200]}",
                entropy=shannon_entropy(secret),
            ))
