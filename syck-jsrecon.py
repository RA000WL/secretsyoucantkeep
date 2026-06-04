#!/usr/bin/env python3
"""
syck-jsrecon.py — thin wrapper around ``syck-hunt --deep-js``.

Usage — see ``syck-hunt --help`` for all options:

  syck-jsrecon example.com                           # full pipeline
  syck-jsrecon example.com -d 2 -rl 10               # depth 2, 10 req/s
  cat js.txt | syck-jsrecon example.com --no-crawl   # pipe JS URLs via stdin
  syck-jsrecon example.com -es                       # with subdomain enum
"""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    script_dir = Path(__file__).parent.resolve()
    hunt_script = script_dir / "syck-hunt.py"

    if not hunt_script.exists():
        print("error: syck-hunt.py not found next to syck-jsrecon.py", file=sys.stderr)
        return 2

    # Inject --deep-js before user args, so CLI parsing still works
    args = ["--deep-js", *sys.argv[1:]]

    import subprocess
    proc = subprocess.run([sys.executable, str(hunt_script), *args])
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
