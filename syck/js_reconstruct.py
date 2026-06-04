"""JS string reconstruction — catches secrets split across concatenations."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from syck.entropy import shannon_entropy
from syck.finding import Finding
from syck.rules import _RULE_RANK

_STRING_LITERAL_RE = re.compile(r"""(["'])((?:[^\\]|\\.)*?)\1""")

_CONCAT_CHAIN_RE = re.compile(
    r"""(["'])((?:[^\\]|\\.)*?)\1\s*\+\s*(["'])((?:[^\\]|\\.)*?)\3"""
)

_JOIN_EXPR_RE = re.compile(
    r"""\[([^\]]+)\]\s*\.\s*join\s*\(\s*(["'])\s*\2\s*\)"""
)

_TEMPLATE_STATIC_RE = re.compile(r"`([^`$]*)`")

_MIN_RECONSTRUCT_LEN = 20


def _reconstruct_concatenation(content: str) -> list[tuple[int, str]]:
    """Find string literal concatenation chains and reconstruct them.
    Returns list of (line_number, reconstructed_string)."""
    results: list[tuple[int, str]] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for m in _CONCAT_CHAIN_RE.finditer(line):
            parts = []
            pos = m.start()
            while pos < len(line):
                lit = _STRING_LITERAL_RE.match(line, pos)
                if not lit:
                    break
                parts.append(lit.group(2))
                pos = lit.end()
                pos = _skip_whitespace_and_plus(line, pos)
                if pos < 0:
                    break
            if len(parts) >= 2:
                reconstructed = "".join(parts)
                if len(reconstructed) >= _MIN_RECONSTRUCT_LEN:
                    results.append((lineno, reconstructed))
    return results


def _skip_whitespace_and_plus(line: str, pos: int) -> int:
    while pos < len(line) and line[pos] in " \t":
        pos += 1
    if pos < len(line) and line[pos] == "+":
        pos += 1
        while pos < len(line) and line[pos] in " \t":
            pos += 1
        return pos
    return -1


def _reconstruct_join(content: str) -> list[tuple[int, str]]:
    """Find array .join('') expressions and reconstruct them.
    Returns list of (line_number, reconstructed_string)."""
    results: list[tuple[int, str]] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for m in _JOIN_EXPR_RE.finditer(line):
            inner = m.group(1)
            parts = _STRING_LITERAL_RE.findall(inner)
            if len(parts) >= 2:
                reconstructed = "".join(p[1] for p in parts)
                if len(reconstructed) >= _MIN_RECONSTRUCT_LEN:
                    results.append((lineno, reconstructed))
    return results


def _reconstruct_template_literals(content: str) -> list[tuple[int, str]]:
    """Find template literals and concatenate their static parts.
    Returns list of (line_number, reconstructed_string)."""
    results: list[tuple[int, str]] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for m in _TEMPLATE_STATIC_RE.finditer(line):
            static = m.group(1)
            if len(static) >= _MIN_RECONSTRUCT_LEN:
                results.append((lineno, static))
    return results


def reconstruct_js(
    content: str,
    path: str | Path,
    rules: list,
    min_rank: int,
    add_fn: Callable,
) -> None:
    for lineno, reconstructed in _reconstruct_concatenation(content):
        _scan_reconstructed(reconstructed, lineno, "reconstructed_concat", path, rules, min_rank, add_fn)
    for lineno, reconstructed in _reconstruct_join(content):
        _scan_reconstructed(reconstructed, lineno, "reconstructed_join", path, rules, min_rank, add_fn)
    for lineno, reconstructed in _reconstruct_template_literals(content):
        _scan_reconstructed(reconstructed, lineno, "reconstructed_template", path, rules, min_rank, add_fn)


def _scan_reconstructed(
    reconstructed: str,
    lineno: int,
    tag: str,
    path: str | Path,
    rules: list,
    min_rank: int,
    add_fn: Callable,
) -> None:
    for rule in rules:
        if _RULE_RANK.get(rule.name, 99) > min_rank:
            continue
        for m in rule.pattern.finditer(reconstructed):
            secret = m.group(0)
            add_fn(Finding(
                file=str(path),
                line=lineno,
                column=m.start() + 1,
                rule=f"{tag}_{rule.name}",
                severity=rule.severity,
                secret=secret,
                context=f"js reconstructed: {reconstructed[:200]}",
                entropy=shannon_entropy(secret),
            ))
