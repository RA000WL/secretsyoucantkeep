from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    secret: str
    context: str
    entropy: float = 0.0
    column: int = 0
    context_before: str = ""
    context_after: str = ""


@dataclass
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
