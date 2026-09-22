#!/usr/bin/env python3
"""
Helper script to launch the local DNS server daemon.
"""

import sys
from idns.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.extend(["server", "--port", "5353"])
    sys.exit(main())
