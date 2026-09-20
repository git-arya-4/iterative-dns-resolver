#!/usr/bin/env python3
"""
Helper script to execute the DNS resolver query CLI.
"""

import sys
from idns.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("resolve")
        sys.argv.append("example.com")
    sys.exit(main())
