from __future__ import annotations

import dataclasses
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from syck.decoder_pipeline import (
    decode_file_content, recursive_decode_and_rescan, recursive_decode_content,
)
from syck.decoders import _decode_and_rescan, _decode_hex_and_rescan
from syck.decoders import _decode_unicode_escapes, _decode_url_encoded
from syck.endpoints import extract_endpoints
from syck.js_reconstruct import reconstruct_js
from syck.entropy import (
    _ENTROPY_EXCLUDE_RE, _ENTROPY_TOKEN_RE, _SECRET_CONTEXT_RE,
    likely_secret, shannon_entropy,
)
from syck.finding import Finding
from syck.json_scanner import _scan_json_file
from syck.rules import RULES, _RULE_RANK, SEVERITY_ORDER
from syck.utils import (
    DEFAULT_MAX_FILE_SIZE, DEFAULT_WORKERS, GREY, YELLOW,
    _HAVE_TQDM, _tqdm, color, debug, is_text_file, iter_files,
)

_BUNDLER_CHUNK_RE = re.compile(r"import\{[A-Za-z, ]+\}from\"\./(?:chunk-|polyfills|main)")


def _is_minified_js(path: Path, content: str) -> bool:
    name = path.name.lower()
    if name.endswith((".min.js", ".bundle.js", ".min.mjs")):
        return True
    if not (name.endswith(".js") or name.endswith(".mjs")):
        return False
    if len(content) < 5000:
        return False
    nlines = content.count("\n")
    if nlines == 0:
        return True
    avg = len(content) / nlines
    if nlines <= 3 or avg > 2000:
        return True
    if _BUNDLER_CHUNK_RE.search(content):
        return True
    return False


def _is_minified_js_streaming(path: Path) -> bool:
    name = path.name.lower()
    if not (name.endswith(".js") or name.endswith(".mjs")):
        return False
    return name.endswith((".min.js", ".bundle.js", ".min.mjs"))


def _scan_file_streaming(path: Path, min_severity: str, high_entropy_scan: bool,
                         decode_base64: bool, decode_hex: bool,
                         extract_endpoints_flag: bool,
                         decode_unicode: bool = False,
                         decode_gzip: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    try:
        f = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return findings

    with f:
        min_rank = SEVERITY_ORDER[min_severity]
        seen: set[tuple[int, str, str]] = set()

        def add(finding: Finding) -> None:
            key = (finding.line, finding.rule, finding.secret[:30])
            if key not in seen:
                seen.add(key)
                findings.append(finding)

        is_minified = _is_minified_js_streaming(path)
        entropy_eligible = high_entropy_scan and not is_minified
        if entropy_eligible:
            try:
                chunk = path.read_bytes()[:65536].decode("utf-8", errors="replace")
                if not _SECRET_CONTEXT_RE.search(chunk):
                    entropy_eligible = False
            except OSError:
                entropy_eligible = False

        prev_lines: list[str] = []

        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n\r")
            context_before = ("\n".join(prev_lines[-2:]) if prev_lines else "")

            for rule in RULES:
                if _RULE_RANK[rule.name] > min_rank:
                    continue
                for match in rule.pattern.finditer(line):
                    raw = match.group(0)
                    if rule.name in ("generic_secret", "dotenv_secret", "basic_auth_header", "wakatime_api_key", "airtable_api_key"):
                        candidate = raw.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")
                        if not likely_secret(candidate, min_len=12, min_entropy=3.2):
                            continue
                    ent = shannon_entropy(raw)
                    add(Finding(
                        file=str(path), line=lineno, column=match.start() + 1,
                        rule=rule.name,
                        severity=rule.severity, secret=raw,
                        context=line.strip()[:200], entropy=ent,
                        context_before=context_before,
                    ))

            if entropy_eligible and _SECRET_CONTEXT_RE.search(line):
                for token in _ENTROPY_TOKEN_RE.findall(line):
                    if _ENTROPY_EXCLUDE_RE.search(token):
                        continue
                    if likely_secret(token, min_len=32, min_entropy=4.5):
                        add(Finding(
                            file=str(path), line=lineno,
                            rule="high_entropy_token", severity="MEDIUM",
                            secret=token, context=line.strip()[:200],
                            entropy=shannon_entropy(token),
                            column=line.find(token) + 1,
                        ))

            if decode_base64:
                _decode_and_rescan(line, path, lineno, RULES, min_rank, add)
            if decode_hex:
                _decode_hex_and_rescan(line, path, lineno, RULES, min_rank, add)
            if decode_unicode:
                _decode_unicode_escapes(line, path, lineno, RULES, min_rank, add)
                _decode_url_encoded(line, path, lineno, RULES, min_rank, add)

            prev_lines.append(line)

    return findings


def scan_file(path: Path, min_severity: str = "LOW",
              high_entropy_scan: bool = True,
              decode_base64: bool = False,
              decode_hex: bool = False,
              extract_endpoints_flag: bool = False,
              decode_gzip: bool = False,
              decode_unicode: bool = False,
              js_reconstruct: bool = False) -> list[Finding]:
    try:
        file_size = path.stat().st_size
    except OSError:
        return []

    if file_size > 1024 * 1024:
        return _scan_file_streaming(path, min_severity, high_entropy_scan,
                                    decode_base64, decode_hex, extract_endpoints_flag,
                                    decode_unicode, decode_gzip)

    findings: list[Finding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    gzip_scanned: set[str] = set()

    if decode_gzip and file_size > 64:
        try:
            raw_bytes = path.read_bytes()
            decompressed_text = decode_file_content(raw_bytes)
            if decompressed_text is not None:
                gzip_min_rank = SEVERITY_ORDER[min_severity]
                gzip_seen: set[tuple[int, str, str]] = set()

                def gzip_add(f: Finding) -> None:
                    key = (f.rule, f.secret[:30])
                    if key not in gzip_seen:
                        gzip_seen.add(key)
                        findings.append(f)
                        gzip_scanned.add(f.secret[:60])

                for g_lineno, g_line in enumerate(decompressed_text.splitlines(), start=1):
                    for rule in RULES:
                        if _RULE_RANK[rule.name] > gzip_min_rank:
                            continue
                        for m in rule.pattern.finditer(g_line):
                            raw = m.group(0)
                            if raw[:60] in gzip_scanned:
                                continue
                            ent = shannon_entropy(raw)
                            gzip_add(Finding(
                                file=str(path), line=g_lineno,
                                column=m.start() + 1,
                                rule=f"gzip_{rule.name}",
                                severity=rule.severity, secret=raw,
                                context=f"gzip decoded: {g_line.strip()[:200]}",
                                entropy=ent,
                            ))
        except OSError:
            pass

    entropy_eligible = high_entropy_scan and not _is_minified_js(path, content)
    if entropy_eligible and not _SECRET_CONTEXT_RE.search(content):
        entropy_eligible = False

    seen: set[tuple[int, str, str]] = set()
    min_rank = SEVERITY_ORDER[min_severity]

    def add(finding: Finding) -> None:
        key = (finding.line, finding.rule, finding.secret[:30])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        context_before = ("\n".join(lines[max(0, lineno - 3):lineno - 1]) if lineno > 1 else "")
        context_after = ("\n".join(lines[lineno:min(len(lines), lineno + 2)]) if lineno < len(lines) else "")

        for rule in RULES:
            if _RULE_RANK[rule.name] > min_rank:
                continue
            for match in rule.pattern.finditer(line):
                raw = match.group(0)
                if rule.name in ("generic_secret", "dotenv_secret", "basic_auth_header", "wakatime_api_key", "airtable_api_key"):
                    candidate = raw.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")
                    if not likely_secret(candidate, min_len=12, min_entropy=3.2):
                        continue
                if raw[:60] in gzip_scanned:
                    continue
                ent = shannon_entropy(raw)
                add(Finding(
                    file=str(path), line=lineno, column=match.start() + 1,
                    rule=rule.name,
                    severity=rule.severity, secret=raw,
                    context=line.strip()[:200], entropy=ent,
                    context_before=context_before,
                    context_after=context_after,
                ))

        if entropy_eligible and _SECRET_CONTEXT_RE.search(line):
            for token in _ENTROPY_TOKEN_RE.findall(line):
                if _ENTROPY_EXCLUDE_RE.search(token):
                    continue
                if token[:60] in gzip_scanned:
                    continue
                if likely_secret(token, min_len=32, min_entropy=4.5):
                    add(Finding(
                        file=str(path), line=lineno,
                        rule="high_entropy_token", severity="MEDIUM",
                        secret=token, context=line.strip()[:200],
                        entropy=shannon_entropy(token),
                        column=line.find(token) + 1,
                    ))

        if decode_base64:
            _decode_and_rescan(line, path, lineno, RULES, min_rank, add)
        if decode_hex:
            _decode_hex_and_rescan(line, path, lineno, RULES, min_rank, add)
        if decode_unicode:
            _decode_unicode_escapes(line, path, lineno, RULES, min_rank, add)
            _decode_url_encoded(line, path, lineno, RULES, min_rank, add)

    _scan_json_file(path, content, RULES, min_rank, add)
    if extract_endpoints_flag:
        findings.extend(extract_endpoints(path, content))

    if js_reconstruct and content:
        reconstruct_js(content, path, RULES, min_rank, add)

    if decode_unicode or decode_gzip:
        recursive_decode_content(content, path, RULES, min_rank, add)

    return findings


def scan_string(content: str, source: str = "<stdin>",
                min_severity: str = "LOW",
                high_entropy_scan: bool = True,
                decode_base64: bool = False,
                decode_hex: bool = False,
                extract_endpoints_flag: bool = False,
                decode_gzip: bool = False,
                decode_unicode: bool = False,
                js_reconstruct: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    if not content:
        return findings

    entropy_eligible = high_entropy_scan and not _is_minified_js(Path(source), content)
    min_rank = SEVERITY_ORDER[min_severity]

    seen: set[tuple[int, str, str]] = set()

    def add(finding: Finding) -> None:
        key = (finding.line, finding.rule, finding.secret[:30])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        context_before = ("\n".join(lines[max(0, lineno - 3):lineno - 1]) if lineno > 1 else "")
        context_after = ("\n".join(lines[lineno:min(len(lines), lineno + 2)]) if lineno < len(lines) else "")

        for rule in RULES:
            if _RULE_RANK[rule.name] > min_rank:
                continue
            for match in rule.pattern.finditer(line):
                raw = match.group(0)
                if rule.name in ("generic_secret", "dotenv_secret", "basic_auth_header", "wakatime_api_key", "airtable_api_key"):
                    candidate = raw.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")
                    if not likely_secret(candidate, min_len=12, min_entropy=3.2):
                        continue
                ent = shannon_entropy(raw)
                add(Finding(
                    file=source, line=lineno, column=match.start() + 1,
                    rule=rule.name,
                    severity=rule.severity, secret=raw,
                    context=line.strip()[:200], entropy=ent,
                    context_before=context_before,
                    context_after=context_after,
                ))

        if entropy_eligible and _SECRET_CONTEXT_RE.search(line):
            for token in _ENTROPY_TOKEN_RE.findall(line):
                if _ENTROPY_EXCLUDE_RE.search(token):
                    continue
                if likely_secret(token, min_len=32, min_entropy=4.5):
                    add(Finding(
                        file=source, line=lineno,
                        rule="high_entropy_token", severity="MEDIUM",
                        secret=token, context=line.strip()[:200],
                        entropy=shannon_entropy(token),
                        column=line.find(token) + 1,
                    ))

        if decode_base64:
            _decode_and_rescan(line, source, lineno, RULES, min_rank, add)
        if decode_hex:
            _decode_hex_and_rescan(line, source, lineno, RULES, min_rank, add)
        if decode_unicode:
            _decode_unicode_escapes(line, source, lineno, RULES, min_rank, add)
            _decode_url_encoded(line, source, lineno, RULES, min_rank, add)

    if source.endswith(".json"):
        _scan_json_file(source, content, RULES, min_rank, add)
    if extract_endpoints_flag:
        findings.extend(extract_endpoints(Path(source), content))

    if js_reconstruct and content:
        reconstruct_js(content, source, RULES, min_rank, add)

    if decode_unicode or decode_gzip:
        recursive_decode_content(content, source, RULES, min_rank, add)

    return findings


_SKIP_SUFFIXES: tuple[str, ...] = ()


def _should_skip_file(path: Path) -> bool:
    return path.suffix.lower() in _SKIP_SUFFIXES


def _collect_files(targets: list[Path], skip_binary: bool,
                   follow_symlinks: bool,
                   exclude_patterns: list[re.Pattern[str]] | None,
                   max_file_size: int) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        if target.is_file():
            if _should_skip_file(target):
                continue
            if skip_binary and not is_text_file(target):
                continue
            if max_file_size:
                try:
                    if target.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue
            files.append(target)
        elif target.is_dir():
            for path in iter_files(target, follow_symlinks, exclude_patterns, max_file_size):
                if _should_skip_file(path):
                    continue
                if skip_binary and not is_text_file(path):
                    continue
                files.append(path)
        else:
            print(color(f"[WARN] skipping unknown path: {target}", YELLOW), file=sys.stderr)
    return files


def _safe_name_from_url(url: str) -> str:
    last = url.split("?", 1)[0].rsplit("/", 1)[-1] or "index.html"
    name = "".join(c for c in last if c.isalnum() or c in "._-")
    if not name:
        name = "index.html"
    return name[:80]


def _fetch_url(url: str, dest_dir: Path, timeout: int = 20) -> Path | None:
    name = _safe_name_from_url(url)
    dest = dest_dir / name
    i = 1
    while dest.exists():
        stem, suf = dest.stem, dest.suffix
        dest = dest_dir / f"{stem}_{i}{suf}"
        i += 1
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syck/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(color(f"[!] failed to fetch {url}: {exc}", YELLOW),
              file=sys.stderr)
        return None
    if not data:
        return None
    try:
        dest.write_bytes(data)
    except OSError as exc:
        print(color(f"[!] failed to write {dest}: {exc}", YELLOW),
              file=sys.stderr)
        return None
    print(color(f"[+] fetched {url} → {dest.name} ({len(data):,} bytes)",
                GREY), file=sys.stderr)
    return dest


def scan_paths(
    targets: list[Path],
    skip_binary: bool = True,
    follow_symlinks: bool = False,
    min_severity: str = "LOW",
    high_entropy_scan: bool = True,
    decode_base64: bool = False,
    decode_hex: bool = False,
    exclude_patterns: list[re.Pattern[str]] | None = None,
    workers: int = DEFAULT_WORKERS,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    progress: bool = False,
    extract_endpoints_flag: bool = False,
    cache: object = None,
    decode_gzip: bool = False,
    decode_unicode: bool = False,
    js_reconstruct: bool = False,
) -> list[Finding]:
    if cache is not None:
        from syck_cache import SyckCache
        assert isinstance(cache, SyckCache), "cache must be a SyckCache instance"

    files = _collect_files(targets, skip_binary, follow_symlinks,
                           exclude_patterns, max_file_size)
    total = len(files)

    if total == 0:
        return []

    per_file: dict[str, list[Finding]] = {}
    use_tqdm = _HAVE_TQDM and (progress or total > 20)
    show_simple = not use_tqdm and (progress or total > 20)

    if show_simple:
        print(color(f"[*] Scanning {total} file(s) with {workers} worker(s)…", GREY),
              file=sys.stderr)
    debug(f"collected {total} files across {len(targets)} target(s)")
    debug(f"using {workers} workers, "
          f"max_file_size={max_file_size}, "
          f"min_severity={min_severity}")

    done = 0
    uncached: list[Path] = files
    if cache is not None:
        uncached = []
        for f in files:
            cached = cache.get(f, min_severity)
            if cached is not None:
                per_file[str(f)] = [
                    Finding(**item) if isinstance(item, dict) else item
                    for item in cached
                ]
                done += 1
            else:
                uncached.append(f)
        if show_simple and done > 0:
            print(color(f"  [{done}/{total}] from cache, {len(uncached)} to scan…", GREY),
                  file=sys.stderr)
        debug(f"cache: {done} files from cache, {len(uncached)} to scan")

    if uncached:
        _scan_args = (min_severity, high_entropy_scan, decode_base64, decode_hex, extract_endpoints_flag, decode_gzip, decode_unicode, js_reconstruct)
        n_uncached = len(uncached)

        if workers <= 1 or total <= 1:
            if use_tqdm:
                pbar = _tqdm(total=total, desc="Scanning", unit="file", leave=False)
                pbar.update(done)
            for f in uncached:
                debug(f"scanning {f}")
                ff = scan_file(f, *_scan_args)
                per_file[str(f)] = ff
                done += 1
                if use_tqdm:
                    pbar.update(1)
                    pbar.set_postfix(findings=len([ff for v in per_file.values() for ff in v]), refresh=False)
                elif show_simple and done % max(1, total // 20) == 0:
                    print(color(f"\r  [{done}/{total}] files scanned…", GREY),
                          end="", file=sys.stderr)
            if use_tqdm:
                pbar.close()
            if show_simple:
                print(color(f"\r  [{total}/{total}] files scanned.      ", GREY), file=sys.stderr)
        else:
            use_processes = sys.platform.startswith("linux") and workers > 4 and n_uncached > 50
            Executor = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
            debug(f"executor: {'ProcessPool' if use_processes else 'Thread'}Pool "
                  f"({workers} workers, {n_uncached} uncached files)")
            if use_tqdm:
                pbar = _tqdm(total=total, desc="Scanning", unit="file", leave=False)
                pbar.update(done)
            with Executor(max_workers=workers) as exe:
                futs = {exe.submit(scan_file, f, *_scan_args): f for f in uncached}
                for fut in as_completed(futs):
                    path = futs[fut]
                    try:
                        per_file[str(path)] = fut.result()
                    except Exception as exc:
                        print(color(f"[WARN] scan failed for {path}: {exc}", YELLOW),
                              file=sys.stderr)
                        debug(f"scan_file error for {path}: {exc}")
                        per_file[str(path)] = []
                    done += 1
                    if use_tqdm:
                        pbar.update(1)
                        pbar.set_postfix(findings=len([ff for v in per_file.values() for ff in v]), refresh=False)
                    elif show_simple and done % max(1, total // 20) == 0:
                        print(color(f"\r  [{done}/{total}] files scanned, "
                                    f"{len([ff for v in per_file.values() for ff in v])} finding(s)…", GREY),
                              end="", file=sys.stderr)
            if use_tqdm:
                pbar.close()
            if show_simple:
                print(color(f"\r  [{total}/{total}] files scanned.      ", GREY), file=sys.stderr)

        if cache is not None:
            for f in uncached:
                cache.put(f, per_file.get(str(f), []), min_severity)

    findings = [ff for v in per_file.values() for ff in v]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    counts: dict[tuple, int] = {}

    for f in findings:
        key = (f.rule, f.secret)
        if key not in seen:
            seen[key] = f
            counts[key] = 1
        else:
            counts[key] += 1

    result = []
    for key, f in seen.items():
        n = counts[key]
        if n > 1:
            import dataclasses
            f = dataclasses.replace(
                f,
                context=f"{f.context}  [also found in {n - 1} other file(s)]"
            )
        result.append(f)

    result.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.file, x.line))
    return result


_SEVERITY_STEPS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_NON_PROD_PATH_PARTS: set[str] = {
    "test", "tests", "spec", "specs", "__tests__",
    "example", "examples", "demo", "demos", "samples",
    "dummy", "mock", "mocks", "fixtures", "fixture", "stubs",
    "vendor", "third_party",
}

_PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)\b(?:example|placeholder|changeme|change_me|your[-_](?:key|secret|token|password)|"
    r"sample|TODO|FIXME|xxxxx|yyyyy|test[-_]?value|dummy)\b"
)


def _downgrade_fp_findings(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        sev = f.severity
        file_parts = Path(f.file).parts
        if any(part in _NON_PROD_PATH_PARTS for part in file_parts):
            idx = _SEVERITY_STEPS.index(sev) if sev in _SEVERITY_STEPS else -1
            if 0 <= idx < len(_SEVERITY_STEPS) - 1:
                sev = _SEVERITY_STEPS[idx + 1]
        if sev != "INFO" and _PLACEHOLDER_PATTERNS.search(f.context):
            sev = "INFO"
        if sev != f.severity:
            f = dataclasses.replace(f, severity=sev)
        out.append(f)
    return out
