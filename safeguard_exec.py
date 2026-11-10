#!/usr/bin/env python3
"""
safeguard_exec.py — Direct One-Shot SafeGuard Transaction Execution CLI.

Executes an on-chain transaction under Hermes SafeGuard EVM simulation protection.
Zero grep, zero file inspection, zero latency.

Usage:
    python3 safeguard_exec.py <target_address> [value_in_eth] [calldata_hex]
Example:
    python3 safeguard_exec.py 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 0 0xd8a17684
"""

import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import __init__ as safeguard


def main():
    args = sys.argv[1:]
    if not args:
        print("⚠️ Usage: python3 safeguard_exec.py <target_address> [value_in_eth, default 0] [calldata_hex, default 0x]")
        sys.exit(1)

    raw_args = " ".join(args)
    result = safeguard.safeguard_exec_command_handler(raw_args)
    print(result)


if __name__ == "__main__":
    main()

