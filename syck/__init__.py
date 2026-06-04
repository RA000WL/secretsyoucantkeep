"""syck — local secrets scanner for bug bounty hunters."""

from syck.finding import Finding, Rule
from syck.formatters import FORMATTERS, format_json, format_text, format_sarif, format_markdown, format_csv, format_html
from syck.git_scanner import scan_git_history
from syck.rules import RULES, SEVERITY_ORDER, _RULE_RANK, load_custom_rules
from syck.scanner import (
    _fetch_url, deduplicate_findings, scan_file, scan_paths, scan_string,
)
from syck.utils import color, debug, is_text_file, parse_size, iter_files

__all__ = [
    "Finding", "Rule",
    "RULES", "SEVERITY_ORDER", "_RULE_RANK", "load_custom_rules",
    "scan_file", "scan_string", "scan_paths", "scan_git_history",
    "deduplicate_findings", "_fetch_url",
    "format_json", "format_text", "format_sarif", "format_markdown", "format_csv", "format_html",
    "FORMATTERS",
    "color", "debug", "is_text_file", "parse_size", "iter_files",
]
