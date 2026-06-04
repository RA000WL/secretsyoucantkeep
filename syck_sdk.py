"""
syck_sdk.py — Programmatic Python SDK for syck.

Usage:
    from syck_sdk import scan, scan_file, scan_url, validate

    results = scan("./my-repo", severity="HIGH")
    for finding in results.findings:
        print(f"{finding.rule}: {finding.secret}")

    # Validate live secrets
    from syck_sdk import validate
    validations = validate(results.findings)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class Summary:
    total: int
    by_severity: dict[str, int]
    by_rule: dict[str, int]
    files_hit: int


@dataclass
class ScanResult:
    findings: list
    summary: Summary
    duration: float
    files_scanned: int


def scan(
    paths: str | Path | Iterable[str | Path],
    severity: str = "LOW",
    workers: int = 4,
    redact: bool = False,
    high_entropy_scan: bool = True,
    decode_base64: bool = True,
    decode_hex: bool = False,
    follow_symlinks: bool = False,
    max_file_size: str = "10M",
    exclude: list[str] | None = None,
    endpoints: bool = False,
    git_history: bool = False,
    validate_secrets: bool = False,
    no_cache: bool = False,
) -> ScanResult:
    """Scan files/directories for exposed secrets.

    Args:
        paths: File path(s) or directory path(s) to scan.
        severity: Minimum severity to report.
        workers: Number of parallel scan workers.
        redact: Mask secret values in findings.
        high_entropy_scan: Enable high-entropy token detection.
        decode_base64: Decode base64 strings and re-scan.
        decode_hex: Decode hex strings and re-scan.
        follow_symlinks: Follow symbolic links.
        max_file_size: Maximum file size to scan (e.g. "10M", "1G").
        exclude: Regex patterns for paths to exclude.
        endpoints: Extract API endpoints from source files.
        git_history: Scan git history for secrets in deleted files.
        validate_secrets: Validate found secrets against provider APIs.
        no_cache: Disable file content cache.

    Returns:
        ScanResult with findings and summary.
    """
    import time
    import sys
    import re as _re
    from syck import (
        scan_paths, scan_git_history, deduplicate_findings,
        format_json, parse_size,
    )

    # Normalize paths
    if isinstance(paths, (str, Path)):
        path_list = [Path(paths)]
    else:
        path_list = [Path(p) if isinstance(p, str) else p for p in paths]

    # Resolve paths
    targets = []
    for p in path_list:
        resolved = p.resolve()
        if resolved.exists():
            targets.append(resolved)
        else:
            print(f"[!] path does not exist: {p}", file=sys.stderr)

    if not targets:
        return ScanResult(
            findings=[], summary=Summary(0, {}, {}, 0),
            duration=0.0, files_scanned=0,
        )

    max_file_size_bytes = parse_size(max_file_size) if isinstance(max_file_size, str) else max_file_size
    exclude_patterns = [_re.compile(pat) for pat in (exclude or [])]

    # Initialize cache
    cache = None
    if not no_cache:
        try:
            from syck_cache import SyckCache
            cache = SyckCache()
        except Exception:
            pass

    start = time.time()

    findings = scan_paths(
        targets=targets,
        skip_binary=True,
        follow_symlinks=follow_symlinks,
        min_severity=severity,
        high_entropy_scan=high_entropy_scan,
        decode_base64=decode_base64,
        decode_hex=decode_hex,
        exclude_patterns=exclude_patterns or None,
        workers=max(1, workers),
        max_file_size=max_file_size_bytes,
        progress=False,
        extract_endpoints_flag=endpoints,
        cache=cache,
    )

    # Git history
    if git_history:
        for target in targets:
            if (target / ".git").exists():
                findings.extend(scan_git_history(target, severity, max(1, workers)))

    findings = deduplicate_findings(findings)

    # Validate
    if validate_secrets and findings:
        try:
            from syck_validate import validate_findings
            validate_findings(findings)
        except ImportError:
            pass

    duration = time.time() - start

    # Build summary
    counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        rule_counts[f.rule] = rule_counts.get(f.rule, 0) + 1

    files_hit = len({f.file for f in findings})
    summary = Summary(
        total=len(findings),
        by_severity=counts,
        by_rule=rule_counts,
        files_hit=files_hit,
    )

    return ScanResult(
        findings=findings,
        summary=summary,
        duration=duration,
        files_scanned=len(targets),
    )


def scan_file(file_path: str | Path, severity: str = "LOW",
              decode_base64: bool = True, decode_hex: bool = False,
              endpoints: bool = False) -> list:
    """Scan a single file for secrets.

    Args:
        file_path: Path to the file.
        severity: Minimum severity to report.
        decode_base64: Decode base64 strings and re-scan.
        decode_hex: Decode hex strings and re-scan.
        endpoints: Extract API endpoints.

    Returns:
        List of Finding objects.
    """
    from syck import scan_file as _scan_file
    from pathlib import Path
    return _scan_file(
        Path(file_path), min_severity=severity,
        decode_base64=decode_base64, decode_hex=decode_hex,
        extract_endpoints_flag=endpoints,
    )


def scan_url(url: str, severity: str = "LOW", **kwargs) -> list:
    """Scan a remote URL for secrets.

    Downloads the URL to a temp file, scans it, and returns findings.

    Args:
        url: HTTP or HTTPS URL to a file (e.g. JS bundle).
        severity: Minimum severity to report.

    Returns:
        List of Finding objects.
    """
    import tempfile
    import shutil
    from syck import _fetch_url, scan_file
    from pathlib import Path

    temp_dir = Path(tempfile.mkdtemp(prefix="syck-sdk-"))
    try:
        fetched = _fetch_url(url, temp_dir)
        if fetched is None:
            return []
        return scan_file(fetched, min_severity=severity, **kwargs)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def validate(findings: list, workers: int = 5) -> dict:
    """Validate found secrets against provider APIs.

    Args:
        findings: List of Finding objects from scan().
        workers: Number of concurrent validation workers.

    Returns:
        Dict keyed by (rule_name, secret_preview) of ValidationResult.
    """
    try:
        from syck_validate import validate_findings
        return validate_findings(findings, workers)
    except ImportError:
        print("[!] syck_validate.py not found", file=sys.stderr)
        return {}


def list_rules() -> list[dict]:
    """List all available detection rules.

    Returns:
        List of dicts with 'name', 'severity', 'pattern' keys.
    """
    from syck import RULES
    return [
        {"name": r.name, "severity": r.severity, "pattern": r.pattern.pattern}
        for r in RULES
    ]
