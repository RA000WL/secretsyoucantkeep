#!/usr/bin/env python3
"""syck_server.py — backcompat shim for syck/server/ package."""
import sys
from syck.server.__main__ import main
sys.exit(main())
