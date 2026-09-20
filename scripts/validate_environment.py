#!/usr/bin/env python3
"""
System environment validator script.
"""

import sys
from pathlib import Path


def validate():
    print("[IDNS VALIDATOR] Checking environment and architecture...")
    python_ver = sys.version_info
    print(f"  Python version: {python_ver.major}.{python_ver.minor}.{python_ver.micro}")
    if python_ver < (3, 10):
        print("  ❌ ERROR: Python 3.10 or higher is required.")
        return 1

    root_hints = Path("config/root_hints.json")
    if root_hints.is_file():
        print("  ✓ Config root_hints.json found.")
    else:
        print("  ❌ ERROR: config/root_hints.json missing.")
        return 1

    try:
        import idns
        import idns.contracts
        import idns.errors
        import idns.cli
        import idns.core
        print("  ✓ Single package 'idns' imported successfully.")
    except ImportError as e:
        print(f"  ❌ ERROR importing idns package: {e}")
        return 1

    print("[IDNS VALIDATOR] Environment validation PASSED cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
