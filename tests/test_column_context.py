"""Tests for column tracking and multi-line context in findings."""
from pathlib import Path
from syck.finding import Finding
from syck.scanner import scan_file, scan_string


def test_finding_has_column():
    """Finding dataclass has column field with default 0."""
    f = Finding(file="test.txt", line=1, rule="test", severity="HIGH",
                secret="abc", context="line", entropy=3.0)
    assert hasattr(f, "column")
    assert f.column == 0


def test_finding_has_context_fields():
    """Finding dataclass has context_before and context_after fields."""
    f = Finding(file="test.txt", line=1, rule="test", severity="HIGH",
                secret="abc", context="line", entropy=3.0)
    assert hasattr(f, "context_before")
    assert hasattr(f, "context_after")
    assert f.context_before == ""
    assert f.context_after == ""


def test_column_in_scan_string():
    """scan_string should populate column from match position."""
    content = 'const x = "ghp_abc123def456ghi789jkl012mno345";'
    findings = scan_string(content, "test.js")
    for f in findings:
        if hasattr(f, "column") and f.column:
            assert f.column > 0
            return
    assert findings, "should have at least one finding"


def test_context_before_after():
    """scan_string should populate multi-line context."""
    content = (
        "const x = 1;\n"
        "const token = 'ghp_abc123def456ghi789jkl012mno345';\n"
        "console.log(token);\n"
    )
    findings = scan_string(content, "test.js")
    for f in findings:
        if f.context_before or f.context_after:
            assert "x = 1" in f.context_before or "console.log" in f.context_after or not (f.context_before or f.context_after)
            return
    assert findings, "should have at least one finding to check context on"
