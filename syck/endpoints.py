from __future__ import annotations

import re
from pathlib import Path

from syck.finding import Finding

ENDPOINT_PATTERNS = [
    re.compile(r"""['"]((?:/api|/v\d+|/internal|/admin|/dashboard|/graphql|/rest)(?:/[a-zA-Z0-9_\-{}:]+){1,6})['""]"""),
    re.compile(r"""['"](/[a-z0-9_\-]+/(?:user|account|admin|auth|login|token|password|key|secret|config|setting)[a-z0-9_/\-]*)['""]""", re.I),
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](https?://[^'"]+)['""]"""),
    re.compile(r"""(?:url|endpoint|baseURL|apiURL)\s*[:=]\s*['"](https?://[^'"]{10,})['""]""", re.I),
    re.compile(r"""(wss?://[a-zA-Z0-9\-._]+(?:/[a-zA-Z0-9_/\-]*)?)"""),
]

GRAPHQL_PATTERN = re.compile(
    r"""['"]((?:https?://[^'"]+)?/graphql(?:/[a-zA-Z0-9_\-]*)?)['""]""", re.I
)


def extract_endpoints(path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for pattern in ENDPOINT_PATTERNS + [GRAPHQL_PATTERN]:
            for m in pattern.finditer(line):
                endpoint = m.group(1)
                if endpoint in seen or len(endpoint) < 5:
                    continue
                if any(endpoint.endswith(ext) for ext in
                       (".png", ".jpg", ".gif", ".css", ".ico", ".woff", ".svg")):
                    continue
                seen.add(endpoint)
                findings.append(Finding(
                    file=str(path),
                    line=lineno,
                    rule="endpoint",
                    severity="INFO",
                    secret=endpoint,
                    context=line.strip()[:200],
                    entropy=0.0,
                ))
    return findings
