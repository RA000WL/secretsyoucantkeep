"""Tests for individual decoders — base64, hex, unicode escapes, URL encoding."""
from syck.decoders import (
    _decode_and_rescan, _decode_hex_and_rescan,
    _decode_unicode_escapes, _decode_url_encoded,
)
from syck.finding import Finding
from syck.rules import RULES, _RULE_RANK, SEVERITY_ORDER


def _make_add_fn(results: list):
    def add_fn(f: Finding) -> None:
        results.append(f)
    return add_fn


def test_base64_decoder():
    line = 'ghp_xxx secret: Z2l0aHViX3BhdF8xMUE0NUZCMTU0NzNBMUZCX2FnVmZ4RndYcHhoV3JjNXds'
    results = []
    add_fn = _make_add_fn(results)
    _decode_and_rescan(line, "test.txt", 1, RULES, SEVERITY_ORDER["HIGH"], add_fn)
    assert len(results) > 0, "base64 decoder should find secrets in the decoded text"
    assert any("base64_" in r.rule for r in results), "findings should be tagged with base64_ prefix"


def test_hex_decoder():
    line = 'secret: 6769746875625f7061745f313141343546423135343733413146425f616756667846775978687757726335776c'
    results = []
    add_fn = _make_add_fn(results)
    _decode_hex_and_rescan(line, "test.txt", 1, RULES, SEVERITY_ORDER["HIGH"], add_fn)
    assert len(results) > 0, "hex decoder should find secrets in the decoded text"
    assert any("hex_" in r.rule for r in results), "findings should be tagged with hex_ prefix"


def test_unicode_escapes():
    ghp_token = 'ghp_abc123def456ghi789jkl012mno345pqr678'
    escaped = ''.join(f'\\u{ord(c):04x}' for c in ghp_token)
    line = 'token = "' + escaped + '"'
    results = []
    add_fn = _make_add_fn(results)
    _decode_unicode_escapes(line, "test.js", 1, RULES, SEVERITY_ORDER["LOW"], add_fn)
    assert len(results) > 0, "unicode decoder should find secrets"
    assert any("unicode_" in r.rule for r in results), "findings should be tagged with unicode_ prefix"


def test_url_encoded():
    ghp_token = 'ghp_abc123def456ghi789jkl012mno345pqr678'
    encoded = ''.join(f'%{ord(c):02x}' for c in ghp_token)
    line = 'token=' + encoded
    results = []
    add_fn = _make_add_fn(results)
    _decode_url_encoded(line, "test.js", 1, RULES, SEVERITY_ORDER["LOW"], add_fn)
    assert len(results) > 0, "URL decoder should find secrets"
    assert any("url_" in r.rule for r in results), "findings should be tagged with url_ prefix"
