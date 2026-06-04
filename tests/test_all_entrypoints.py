"""Verify all entry points compile and run without errors."""
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).parent
ROOT = HERE.parent


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m"] + args,
        capture_output=True, text=True, timeout=30,
        cwd=ROOT,
    )


def test_syck_module_imports():
    """All syck/ package modules import cleanly."""
    import syck
    import syck.scanner
    import syck.rules
    import syck.decoders
    import syck.decoder_pipeline
    import syck.js_reconstruct
    import syck.cli
    import syck.formatters
    import syck.finding
    import syck.entropy
    import syck.json_scanner
    import syck.ignore
    import syck.config
    import syck.endpoints
    import syck.git_scanner
    import syck.hunt
    import syck.hunt.recon
    import syck.hunt.stages
    import syck.async_fetch
    import syck.server
    assert syck.scan_file


def test_syck_help():
    result = _run(["syck", "--help"])
    assert result.returncode == 0
    assert "--decode-gzip" in result.stdout
    assert "--decode-unicode" in result.stdout
    assert "--js-reconstruct" in result.stdout


def test_syck_list_rules():
    result = _run(["syck", "--list-rules"])
    assert result.returncode == 0
    assert "github_pat" in result.stdout or "generic_secret" in result.stdout


def test_syck_scan_empty():
    """Scan an empty temp dir produces no output."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(["syck", tmp, "--severity", "LOW"])
        assert result.returncode == 0


def test_syck_scan_with_findings():
    """Scan a file with a known secret pattern."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "test.js"
        f.write_text('const token = "ghp_abc123def456ghi789jkl012mno345";\n')
        result = _run(["syck", str(f)])
        assert result.returncode == 1
        assert "ghp_" in result.stdout


def test_syck_scan_json():
    """Scan a JSON file with secret keys."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "config.json"
        f.write_text('{"password": "supersecretvalue12345", "api_key": "12345abcdef"}\n')
        result = _run(["syck", str(f)])
        assert result.returncode == 1


def test_syck_scan_json_output():
    """Verify --format json produces valid JSON."""
    import tempfile
    import json
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "test.js"
        f.write_text('const token = "ghp_abc123def456ghi789jkl012mno345";\n')
        result = _run(["syck", str(f), "--format", "json"])
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) > 0
        assert "column" in data[0]
        assert "context_before" in data[0]
        assert "context_after" in data[0]


def test_syck_scan_sarif_output():
    """Verify --format sarif produces valid SARIF JSON with column."""
    import tempfile
    import json
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "test.js"
        f.write_text('const token = "ghp_abc123def456ghi789jkl012mno345";\n')
        result = _run(["syck", str(f), "--format", "sarif"])
        assert result.returncode == 1
        sarif = json.loads(result.stdout)
        assert "runs" in sarif
        run = sarif["runs"][0]
        assert "results" in run
        if run["results"]:
            loc = run["results"][0]["locations"][0]["physicalLocation"]["region"]
            if "startColumn" in loc:
                assert loc["startColumn"] > 0


def test_syck_scan_csv_output():
    """Verify --format csv includes column and context fields."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "test.js"
        f.write_text('const token = "ghp_abc123def456ghi789jkl012mno345";\n')
        result = _run(["syck", str(f), "--format", "csv"])
        assert result.returncode == 1
        assert "column" in result.stdout
        assert "context_before" in result.stdout
        assert "context_after" in result.stdout


def test_all_root_shims_import():
    """All 5 root shims import without errors."""
    import syck
    import syck_async
    import syck_cache
    import syck_rpc
    import syck_sarif
    import syck_sdk
    import syck_validate
    import syck_webhook
    assert syck
    assert syck_async
    assert syck_rpc


def test_decoder_pipeline_modules():
    """New modules import without error."""
    import syck.decoder_pipeline
    import syck.js_reconstruct
    assert syck.decoder_pipeline
    assert syck.js_reconstruct


def test_advanced_flags_help():
    """Assert new CLI flags appear in --help."""
    result = _run(["syck", "--help"])
    assert "--decode-gzip" in result.stdout
    assert "--decode-unicode" in result.stdout
    assert "--js-reconstruct" in result.stdout
