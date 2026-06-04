from __future__ import annotations

import hashlib
from pathlib import Path

from syck.finding import Finding


def _finding_fingerprint(f: Finding) -> str:
    raw = f"{f.rule}:{f.secret[:60]}:{Path(f.file).name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def load_ignore_list(path: Path | None = None) -> set[str]:
    candidates = [Path(".syckignore")]
    if path:
        candidates.insert(0, path)
    for p in candidates:
        if p.exists():
            lines = p.read_text(encoding="utf-8").splitlines()
            return {
                line.split("#")[0].strip()
                for line in lines
                if line.strip() and not line.startswith("#")
            }
    return set()


def filter_ignored(findings: list[Finding],
                   ignore: set[str]) -> list[Finding]:
    if not ignore:
        return findings
    return [f for f in findings if _finding_fingerprint(f) not in ignore]
