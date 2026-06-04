#!/usr/bin/env python3
"""syck.py — slim shim for the syck/ package."""
import sys
from syck.cli import main
raise SystemExit(main(sys.argv[1:]))
