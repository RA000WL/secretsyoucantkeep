from __future__ import annotations

import json
import re
from pathlib import Path

from syck.entropy import shannon_entropy
from syck.finding import Finding
from syck.rules import _RULE_RANK

_JSON_SECRET_KEYS = re.compile(
    r"(?i)^(?:"
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|access[_-]?token|auth[_-]?token|auth[_-]?key|"
    r"client[_-]?secret|client[_-]?id|"
    r"private[_-]?key|ssh[_-]?key|"
    r"encryption[_-]?key|signing[_-]?key|"
    r"bearer|credential|refresh[_-]?token|"
    r"session[_-]?key|secret[_-]?key|master[_-]?key"
    r")$"
)

_JSON_MAX_SCAN_SIZE = 10 * 1024 * 1024


def _scan_json_value(value: object, key_path: str, path: str | Path,
                     rules: list, min_rank: int, add_fn) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            kp = f"{key_path}.{k}" if key_path else k
            _scan_json_value(v, kp, path, rules, min_rank, add_fn)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _scan_json_value(v, f"{key_path}[{i}]", path, rules, min_rank, add_fn)
    elif isinstance(value, str):
        if not value:
            return
        key_name = key_path.rsplit(".", 1)[-1] if "." in key_path else key_path
        if _JSON_SECRET_KEYS.match(key_name):
            ent = shannon_entropy(value)
            if len(value) >= 8 and not value.isdigit() and ent >= 3.0:
                add_fn(Finding(
                    file=str(path),
                    line=0,
                    rule=f"json_{key_name}",
                    severity="MEDIUM",
                    secret=value[:500],
                    context=f"json key: {key_path}",
                    entropy=ent,
                ))
        for rule in rules:
            if _RULE_RANK.get(rule.name, 99) > min_rank:
                continue
            for m in rule.pattern.finditer(value):
                secret = m.group(0)
                add_fn(Finding(
                    file=str(path),
                    line=0,
                    rule=f"json_{rule.name}",
                    severity=rule.severity,
                    secret=secret,
                    context=f"json key: {key_path}",
                    entropy=shannon_entropy(secret),
                ))


def _scan_json_file(path: str | Path, content: str, rules: list,
                    min_rank: int, add_fn) -> None:
    if not path.suffix.lower() == ".json":
        return
    if len(content) > _JSON_MAX_SCAN_SIZE:
        return
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    _scan_json_value(data, "", path, rules, min_rank, add_fn)
