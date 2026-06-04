"""Tests for JS string reconstruction — concatenation, join, template literals."""
from syck.js_reconstruct import (
    _reconstruct_concatenation, _reconstruct_join,
    _reconstruct_template_literals, reconstruct_js,
)
from syck.finding import Finding
from syck.rules import RULES, _RULE_RANK, SEVERITY_ORDER


def _make_add_fn(results: list):
    def add_fn(f: Finding) -> None:
        results.append(f)
    return add_fn


def test_concat_two_parts():
    content = 'const token = "ghp_" + "abc123def456ghi789jkl012mno345";'
    results = _reconstruct_concatenation(content)
    assert len(results) > 0
    text = results[0][1]
    assert "ghp_" in text
    assert "abc123def456ghi789jkl012mno345" in text


def test_concat_three_parts():
    content = 'const token = "gh" + "p_" + "abc123def456ghi789jkl012mno345";'
    results = _reconstruct_concatenation(content)
    assert len(results) > 0
    text = results[0][1]
    assert "ghp_" in text


def test_array_join():
    content = 'const token = ["ghp_", "abc123def456ghi789jkl012mno345"].join("");'
    results = _reconstruct_join(content)
    assert len(results) > 0
    text = results[0][1]
    assert "ghp_" in text
    assert "abc123def456ghi789jkl012mno345" in text


def test_template_literal():
    content = 'const token = `ghp_abc123def456ghi789jkl012mno345`;'
    results = _reconstruct_template_literals(content)
    assert len(results) > 0
    assert "ghp_" in results[0][1]


def test_integration_reconstruct_js():
    content = 'const t = "ghp_" + "abc123def456ghi789jkl012mno345";'
    results = []
    add_fn = _make_add_fn(results)
    reconstruct_js(content, "test.js", RULES, SEVERITY_ORDER["LOW"], add_fn)
    assert len(results) > 0, "reconstruct_js should find secrets in reconstructed strings"
    assert any("reconstructed_" in r.rule for r in results), "findings should be tagged with reconstructed_ prefix"
