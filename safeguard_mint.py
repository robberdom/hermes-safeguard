#!/usr/bin/env python3
"""
safeguard_mint.py — Direct One-Shot SafeGuard NFT Mint CLI.

Executes an on-chain NFT mint under Hermes SafeGuard EVM simulation protection.
Zero grep, zero file inspection, zero latency.

Usage:
    python3 safeguard_mint.py <contract_address> [unit_price_in_eth] [quantity]
Example:
    python3 safeguard_mint.py 0x5FbDB2315678afecb367f032d93F642f64180aa3 0.05 1
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
        print("⚠️ Usage: python3 safeguard_mint.py <contract_address> [unit_price_in_eth, default 0.05] [quantity, default 1]")
        sys.exit(1)

    raw_args = " ".join(args)
    result = safeguard.safeguard_mint_command_handler(raw_args)
    print(result)


if __name__ == "__main__":
    main()

