from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone
from html import escape as html_escape

from syck.finding import Finding
from syck.utils import (
    BOLD, CYAN, GREEN, GREY, MAGENTA, RED, YELLOW,
    SEVERITY_COLOR, SEVERITY_SARIF_LEVEL, color,
)


def redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    if len(secret) <= 16:
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _summary_lines(findings: list[Finding]) -> list[str]:
    if not findings:
        return [color("\n✔  No secrets found.", GREEN)]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    files_hit = len({f.file for f in findings})
    total = len(findings)
    lines = [color("\n── Summary ──────────────────────────────", BOLD)]
    lines.append(f"  Files with findings : {color(str(files_hit), YELLOW)}")
    lines.append(f"  Total findings      : {color(str(total), RED if total else GREEN)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"    {sev:<10}  {n}")
    lines.append("")
    return lines


def format_text(findings: list[Finding], redact_secrets: bool = False) -> str:
    lines: list[str] = []
    if findings and not redact_secrets:
        lines.append(color("⚠  WARNING: secrets are shown IN FULL — do not share this output publicly.",
                           YELLOW + BOLD))
        lines.append("")

    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            if current_file is not None:
                lines.append("")
            lines.append(color(f.file, BOLD + MAGENTA))

        sev_col = SEVERITY_COLOR.get(f.severity, "")
        sev_tag = color(f"[{f.severity}]", sev_col)
        rule_tag = color(f"[{f.rule}]", CYAN)
        secret_display = f.secret if not redact_secrets else redact(f.secret)

        loc = f"  {color(str(f.line), GREY)}"
        if f.column:
            loc += f":{color(str(f.column), GREY)}"
        lines.append(f"{loc}  {sev_tag} {rule_tag}  "
                     f"entropy={color(str(f.entropy), GREY)}")
        lines.append(f"       secret : {color(secret_display, YELLOW)}")
        lines.append(f"       context: {color(f.context, GREY)}")
        if f.context_before:
            lines.append(f"       before : {color(f.context_before, GREY)}")
        if f.context_after:
            lines.append(f"       after  : {color(f.context_after, GREY)}")

    lines.extend(_summary_lines(findings))
    return "\n".join(lines) + "\n"


def format_json(findings: list[Finding], redact_secrets: bool = False) -> str:
    data = [asdict(f) for f in findings]
    if redact_secrets:
        for item in data:
            item["secret"] = redact(item["secret"])
    return json.dumps(data, indent=2)


def format_sarif(findings: list[Finding], redact_secrets: bool = False) -> str:
    rules_index: dict[str, int] = {}
    rules_list: list[dict] = []
    for f in findings:
        if f.rule not in rules_index:
            rules_index[f.rule] = len(rules_list)
            rules_list.append({
                "id": f.rule,
                "name": f.rule,
                "shortDescription": {"text": f"Detects {f.rule}."},
                "defaultConfiguration": {
                    "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning"),
                },
            })

    results = []
    for f in findings:
        secret_value = redact(f.secret) if redact_secrets else f.secret
        region: dict = {
            "startLine": f.line,
            "endLine": f.line,
            "snippet": {"text": f.context[:200]},
        }
        if f.column:
            region["startColumn"] = f.column
        results.append({
            "ruleId": f.rule,
            "ruleIndex": rules_index[f.rule],
            "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"Potential {f.rule} exposed."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": region,
                },
                "properties": {"secret": secret_value, "entropy": f.entropy},
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "syck",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/RA000WL/secretsyoucantkeep",
                    "rules": rules_list,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _md_escape(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def format_markdown(findings: list[Finding], redact_secrets: bool = False) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [f"# syck scan report", f"_Generated: {ts}_", ""]

    if not findings:
        lines.append("**No secrets found.**")
        return "\n".join(lines) + "\n"

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    files_hit = len({f.file for f in findings})

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Files with findings:** {files_hit}")
    lines.append(f"- **Total findings:** {len(findings)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"- **{sev}:** {n}")
    lines.append("")

    if not redact_secrets:
        lines.append("> ⚠️ **WARNING:** secrets below are shown IN FULL. Do not paste this report "
                     "into a public issue tracker without redacting first.")
        lines.append("")

    files: dict[str, list[Finding]] = {}
    for f in findings:
        files.setdefault(f.file, []).append(f)

        lines.append("## Findings")
        lines.append("")
        for path, items in files.items():
            lines.append(f"### `{_md_escape(path)}`")
            lines.append("")
            lines.append("| Line | Col | Severity | Rule | Secret | Entropy |")
            lines.append("|------|-----|----------|------|--------|---------|")
            for f_item in items:
                secret = (f"`{_md_escape(f_item.secret)}`" if not redact_secrets
                          else f"`{_md_escape(redact(f_item.secret))}`")
                col = str(f_item.column) if f_item.column else ""
                lines.append(f"| {f_item.line} | {col} | {f_item.severity} | {f_item.rule} | {secret} | {f_item.entropy} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_csv(findings: list[Finding], redact_secrets: bool = False) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["file", "line", "column", "rule", "severity", "secret", "context", "context_before", "context_after", "entropy"])
    for f in findings:
        secret = redact(f.secret) if redact_secrets else f.secret
        writer.writerow([f.file, f.line, f.column, f.rule, f.severity, secret, f.context, f.context_before, f.context_after, f.entropy])
    return buf.getvalue()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>syck report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          margin: 24px; background: #0d1117; color: #c9d1d9; }}
  h1, h2, h3 {{ color: #f0f6fc; }}
  .meta {{ color: #8b949e; font-size: 0.9em; }}
  .warn {{ background: #2d1b00; border-left: 4px solid #d29922; padding: 10px 14px;
           border-radius: 4px; margin: 12px 0; color: #f0c674; }}
  .summary {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
           padding: 10px 14px; font-size: 0.95em; }}
   .CRITICAL {{ color: #f85149; font-weight: 700; }}
   .HIGH     {{ color: #d29922; font-weight: 600; }}
   .MEDIUM   {{ color: #58a6ff; }}
   .LOW      {{ color: #8b949e; }}
   .INFO     {{ color: #3fb950; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #21262d;
            font-size: 0.9em; vertical-align: top; }}
  th {{ background: #161b22; color: #f0f6fc; cursor: pointer; user-select: none; }}
  tr:hover td {{ background: #161b22; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px;
          font-family: "SF Mono", Menlo, Consolas, monospace; word-break: break-all;
          color: #ffa657; }}
  details {{ margin: 8px 0; background: #0d1117; }}
  summary {{ cursor: pointer; padding: 10px 12px; background: #161b22;
             border: 1px solid #30363d; border-radius: 6px; font-weight: 500; }}
  summary:hover {{ background: #1c2128; }}
  .file-name {{ color: #d2a8ff; font-family: "SF Mono", Menlo, monospace; }}
  .context {{ color: #8b949e; font-style: italic; word-break: break-word; }}
  .empty {{ padding: 60px; text-align: center; color: #3fb950; font-size: 1.2em; }}
</style>
</head>
<body>
<h1>syck report</h1>
<p class="meta">Generated: {timestamp} &middot; Tool: syck v2.0.0</p>
{warning}
{body}
</body>
</html>
"""


def format_html(findings: list[Finding], redact_secrets: bool = False) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    warning = ""
    if findings and not redact_secrets:
        warning = ('<div class="warn">⚠ <strong>WARNING:</strong> secrets below are shown IN FULL. '
                   'Do not share this HTML file publicly.</div>')

    if not findings:
        body = '<div class="empty">✔ No secrets found.</div>'
    else:
        files: dict[str, list[Finding]] = {}
        for f in findings:
            files.setdefault(f.file, []).append(f)

        parts: list[str] = ['<div class="summary">']
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts[sev]
            parts.append(f'<div class="card {sev}">{sev}: {n}</div>')
        parts.append(f'<div class="card">Files: {len(files)}</div>')
        parts.append(f'<div class="card">Total: {len(findings)}</div>')
        parts.append('</div>')

        for path, items in files.items():
            parts.append('<details open>')
            parts.append(
                f'<summary><span class="file-name">{html_escape(path)}</span> '
                f'<span class="meta">({len(items)} finding{"s" if len(items) != 1 else ""})</span></summary>'
            )
            parts.append('<table>')
            parts.append('<thead><tr><th>Line</th><th>Col</th><th>Severity</th><th>Rule</th>'
                         '<th>Secret</th><th>Entropy</th><th>Context</th></tr></thead>')
            parts.append('<tbody>')
            for f_item in items:
                secret_disp = (f_item.secret if not redact_secrets else redact(f_item.secret))
                col_str = str(f_item.column) if f_item.column else ""
                parts.append(
                    f'<tr>'
                    f'<td>{f_item.line}</td>'
                    f'<td>{col_str}</td>'
                    f'<td class="{f_item.severity}">{f_item.severity}</td>'
                    f'<td>{html_escape(f_item.rule)}</td>'
                    f'<td><code>{html_escape(secret_disp)}</code></td>'
                    f'<td>{f_item.entropy}</td>'
                    f'<td class="context">{html_escape(f_item.context)}</td>'
                    f'</tr>'
                )
            parts.append('</tbody></table>')
            parts.append('</details>')
        body = "\n".join(parts)

    return _HTML_TEMPLATE.format(timestamp=timestamp, warning=warning, body=body)


FORMATTERS = {
    "text":     format_text,
    "json":     format_json,
    "sarif":    format_sarif,
    "markdown": format_markdown,
    "csv":      format_csv,
    "html":     format_html,
}
