"""
syck_rpc.py — JSON-RPC 2.0 interface for syck over stdin/stdout.

Used by editor extensions, IDE plugins, and other tools that want
to embed syck without subprocess overhead.

Usage:
    echo '{"jsonrpc":"2.0","method":"scan","params":{"paths":[".env"]},"id":1}' \\
        | python syck_rpc.py

Protocol:
    Request:  {"jsonrpc":"2.0","method":"<method>","params":{...},"id":<n>}
    Response: {"jsonrpc":"2.0","result":{...},"id":<n>}
    Error:    {"jsonrpc":"2.0","error":{"code":-1,"message":"..."},"id":<n>}

Methods:
    scan(paths, severity="LOW", ...)   -> ScanResult
    validate(findings, workers=5)      -> dict
    list_rules()                       -> list[Rule]
    health()                           -> {"status": "ok"}
"""
from __future__ import annotations

import json
import sys
import traceback


def _handle_request(request: dict) -> dict:
    method = request.get("method", "")
    params = request.get("params", {})
    req_id = request.get("id")

    if method == "health":
        return {"jsonrpc": "2.0", "result": {"status": "ok", "tool": "syck"}, "id": req_id}

    if method == "list_rules":
        from syck import RULES
        rules = [
            {"name": r.name, "severity": r.severity, "pattern": r.pattern.pattern}
            for r in RULES
        ]
        return {"jsonrpc": "2.0", "result": {"rules": rules, "total": len(rules)}, "id": req_id}

    if method == "scan":
        from syck_sdk import scan
        paths = params.get("paths", [])
        if not paths:
            return _error(req_id, -32602, "No paths provided")
        result = scan(
            paths=paths,
            severity=params.get("severity", "LOW"),
            workers=params.get("workers", 4),
            redact=params.get("redact", False),
            high_entropy_scan=params.get("high_entropy_scan", True),
            decode_base64=params.get("decode_base64", True),
            decode_hex=params.get("decode_hex", False),
            endpoints=params.get("endpoints", False),
            git_history=params.get("git_history", False),
            validate_secrets=params.get("validate", False),
            no_cache=params.get("no_cache", False),
        )
        return {
            "jsonrpc": "2.0",
            "result": {
                "summary": {
                    "total": result.summary.total,
                    "by_severity": result.summary.by_severity,
                    "by_rule": result.summary.by_rule,
                    "files_hit": result.summary.files_hit,
                },
                "duration": round(result.duration, 2),
                "findings": [
                    {
                        "file": f.file,
                        "line": f.line,
                        "rule": f.rule,
                        "severity": f.severity,
                        "secret": f.secret,
                        "context": f.context,
                        "entropy": f.entropy,
                    }
                    for f in result.findings
                ],
            },
            "id": req_id,
        }

    if method == "validate":
        from syck_validate import validate_findings
        findings_data = params.get("findings", [])
        workers = params.get("workers", 5)

        # Reconstruct Finding objects from dicts
        from syck import Finding
        findings = [Finding(**f) for f in findings_data]
        results = validate_findings(findings, workers)

        serialized = {}
        for (rule, secret), result in results.items():
            serialized[f"{rule}:{secret}"] = {
                "rule": result.rule,
                "secret": result.secret,
                "valid": result.valid,
                "detail": result.detail,
            }
        return {
            "jsonrpc": "2.0",
            "result": {"validations": serialized},
            "id": req_id,
        }

    return _error(req_id, -32601, f"Method not found: {method}")


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": req_id}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            print(json.dumps(_error(None, -32700, f"Parse error: {e}")))
            continue
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            print(json.dumps(_error(None, -32600, "Invalid Request")))
            continue
        try:
            response = _handle_request(request)
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            response = _error(request.get("id"), -1, str(e))
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
