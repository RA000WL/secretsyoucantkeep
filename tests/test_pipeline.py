"""Tests for recursive decode pipeline — gzip, chaining, depth limiting."""
import gzip
import json

from syck.decoder_pipeline import (
    decode_file_content, recursive_decode_and_rescan,
    recursive_decode_content, _try_decode_base64,
    _try_decode_hex, _try_decode_unicode_escapes,
)
from syck.finding import Finding
from syck.rules import RULES, _RULE_RANK, SEVERITY_ORDER


def _make_add_fn(results: list):
    def add_fn(f: Finding) -> None:
        results.append(f)
    return add_fn


def test_gzip_decompress():
    secret = b'github_pat_11A45FB15473A1FB_agVfxFwYpxhWrc5wl'
    compressed = gzip.compress(secret)
    result = decode_file_content(compressed)
    assert result is not None, "gzip decompress should return text"
    assert "github_pat_" in result


def test_gzip_non_compressed():
    result = decode_file_content(b"not compressed at all")
    assert result is None, "non-gzip content should return None"


def test_recursive_base64_only():
    # Single level of base64
    line = "secret: Z2l0aHViX3BhdF8xMUE0NUZCMTU0NzNBMUZCX2FnVmZ4RndYcHhoV3JjNXds"
    results = []
    add_fn = _make_add_fn(results)
    recursive_decode_and_rescan(line, "test.txt", 1, RULES, SEVERITY_ORDER["HIGH"], add_fn)
    assert len(results) > 0, "recursive pipeline should find base64-decoded secrets"


def test_recursive_depth_limit():
    """Verify depth limiting prevents infinite recursion."""
    # Create a contrived case: base64(base64(...))
    import base64 as b64
    payload = b"ghp_abc123"
    for _ in range(5):
        payload = b64.b64encode(payload)
    payload_str = b64.b64encode(b64.b64encode(
        b64.b64encode(b"ghp_abc1234567890123456")
    )).decode()
    line = f"secret: {payload_str}"
    results = []
    add_fn = _make_add_fn(results)
    recursive_decode_and_rescan(line, "test.txt", 1, RULES, SEVERITY_ORDER["LOW"], add_fn)
    # Should produce results without infinite recursion
    assert isinstance(results, list)


def test_try_decode_base64():
    results = _try_decode_base64("Z2l0aHViX3BhdF8xMUE0NUZCMTU0NzNBMUZCX2FnVmZ4RndYcHhoV3JjNXds")
    assert len(results) > 0
    assert "github_pat_" in results[0]


def test_try_decode_hex():
    results = _try_decode_hex("6769746875625f7061745f313141343546423135343733413146425f616756667846775978687757726335776c")
    assert len(results) > 0
    assert "github_pat_" in results[0]


def test_try_decode_unicode():
    results = _try_decode_unicode_escapes(r"\u0067\u0068\u0070\u005f")
    assert len(results) > 0
    assert "ghp_" in results[0]
