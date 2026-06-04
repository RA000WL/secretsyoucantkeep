from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from syck.finding import Finding
from syck.scanner import scan_file
from syck.utils import TEXT_EXTENSIONS, color, GREY, YELLOW


def scan_git_history(repo_path: Path, min_severity: str = "LOW",
                     workers: int = 4) -> list[Finding]:
    import subprocess as _sp
    import tempfile as _tf

    findings: list[Finding] = []

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "log",
             "--all", "--format=%H", "--diff-filter=AM"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(color(f"[!] git log failed: {result.stderr[:200]}", YELLOW),
                  file=sys.stderr)
            return findings
        commits = [h.strip() for h in result.stdout.splitlines() if h.strip()]
    except Exception as e:
        print(color(f"[!] git history scan error: {e}", YELLOW), file=sys.stderr)
        return findings

    print(color(f"[*] scanning git history: {len(commits)} commit(s)…", GREY),
          file=sys.stderr)

    seen_secrets: set[tuple] = set()

    for commit in commits:
        try:
            ls = subprocess.run(
                ["git", "-C", str(repo_path), "diff-tree",
                 "--no-commit-id", "-r", "--name-only", commit],
                capture_output=True, text=True, timeout=30
            )
            files_in_commit = [f.strip() for f in ls.stdout.splitlines() if f.strip()]
        except Exception:
            continue

        for filepath in files_in_commit:
            suffix = Path(filepath).suffix.lower()
            if suffix not in TEXT_EXTENSIONS:
                continue
            try:
                cat = subprocess.run(
                    ["git", "-C", str(repo_path), "show", f"{commit}:{filepath}"],
                    capture_output=True, text=True, timeout=15, errors="replace"
                )
                if cat.returncode != 0:
                    continue
                content = cat.stdout
            except Exception:
                continue

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=Path(filepath).suffix,
                delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(content)
                tmp_path = Path(tmp.name)

            try:
                file_findings = scan_file(tmp_path, min_severity)
            finally:
                tmp_path.unlink(missing_ok=True)

            for f in file_findings:
                dedup_key = (f.rule, f.secret[:40])
                if dedup_key not in seen_secrets:
                    seen_secrets.add(dedup_key)
                    findings.append(Finding(
                        file=f"git:{commit[:8]}:{filepath}",
                        line=f.line,
                        rule=f.rule,
                        severity=f.severity,
                        secret=f.secret,
                        context=f.context,
                        entropy=f.entropy,
                    ))

    return findings
