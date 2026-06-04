#!/usr/bin/env python3
"""syck-hunt.py — backcompat shim for syck/hunt/ package."""
import sys
from syck.hunt.cli import main
sys.exit(main(sys.argv[1:]))
