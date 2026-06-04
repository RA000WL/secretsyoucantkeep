"""
syck.server — Lightweight REST API server for syck scanning.

Usage:
    python -m syck.server              # default: http://0.0.0.0:8080
    python -m syck.server --port 9000 --host 127.0.0.1

Endpoints:
    POST /scan          Scan files/directories for secrets
    GET  /scan/<id>     Retrieve scan results
    GET  /rules         List available detection rules
    GET  /health        Health check
"""
from __future__ import annotations

import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


SCANS: dict[str, dict] = {}
HOST = "0.0.0.0"
PORT = 8080
API_KEY: str | None = None
MAX_SCAN_AGE = 3600  # 1 hour


class SyckHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}", file=__import__('sys').stderr)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message}, status)

    def _check_auth(self) -> bool:
        if API_KEY is None:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {API_KEY}"

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        if not self._check_auth():
            self._send_error(401, "Unauthorized")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            self._send_json({"status": "ok", "timestamp": time.time()})

        elif path == "/rules":
            try:
                from syck import RULES
                rules = [
                    {"name": r.name, "severity": r.severity, "pattern": r.pattern.pattern}
                    for r in RULES
                ]
                self._send_json({"rules": rules, "total": len(rules)})
            except Exception as e:
                self._send_error(500, str(e))

        elif path.startswith("/scan/"):
            scan_id = path[len("/scan/"):]
            result = SCANS.get(scan_id)
            if result is None:
                self._send_error(404, "Scan not found")
                return
            self._send_json(result)

        else:
            self._send_error(404, "Not found")

    def do_POST(self):
        if not self._check_auth():
            self._send_error(401, "Unauthorized")
            return

        parsed = urlparse(self.path)
        if parsed.path != "/scan":
            self._send_error(404, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_error(400, "Empty request body")
            return

        try:
            body = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._send_error(400, f"Invalid JSON: {e}")
            return

        paths = body.get("paths", [])
        if not paths:
            self._send_error(400, "No paths provided")
            return

        severity = body.get("severity", "LOW")
        workers = body.get("workers", 4)
        redact = body.get("redact", False)
        endpoints = body.get("endpoints", False)
        git_history = body.get("git_history", False)
        validate = body.get("validate", False)

        from syck_sdk import scan
        result = scan(
            paths=paths,
            severity=severity,
            workers=workers,
            redact=redact,
            endpoints=endpoints,
            git_history=git_history,
            validate_secrets=validate,
        )

        scan_id = uuid.uuid4().hex[:12]
        SCANS[scan_id] = {
            "id": scan_id,
            "status": "completed",
            "timestamp": time.time(),
            "summary": {
                "total": result.summary.total,
                "by_severity": result.summary.by_severity,
                "files_hit": result.summary.files_hit,
            },
            "duration": round(result.duration, 2),
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "rule": f.rule,
                    "severity": f.severity,
                    "secret": f.secret if not redact else f.secret[:4] + "..." + f.secret[-4:],
                    "context": f.context,
                    "entropy": f.entropy,
                }
                for f in result.findings
            ],
        }

        # Clean old scans
        cutoff = time.time() - MAX_SCAN_AGE
        for sid in list(SCANS.keys()):
            if SCANS[sid].get("timestamp", 0) < cutoff:
                del SCANS[sid]

        self._send_json({"id": scan_id, "url": f"/scan/{scan_id}"}, 201)


def serve(host: str = HOST, port: int = PORT, api_key: str | None = None):
    global API_KEY
    API_KEY = api_key
    server = HTTPServer((host, port), SyckHandler)
    print(f"[*] syck server running on http://{host}:{port}", file=__import__('sys').stderr)
    if api_key:
        print(f"[*] API key required via Authorization: Bearer <key>", file=__import__('sys').stderr)
    print(f"    POST /scan   — scan files/directories", file=__import__('sys').stderr)
    print(f"    GET  /rules  — list detection rules", file=__import__('sys').stderr)
    print(f"    GET  /health — health check", file=__import__('sys').stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] shutting down", file=__import__('sys').stderr)
        server.server_close()
