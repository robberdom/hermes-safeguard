"""
Hermes SafeGuard — Schemas (schemas.py)
Declares tool schemas for LLM tool consumption.
Follows the official Hermes Agent 4-file plugin specification:
- plugin.yaml: declares capabilities
- schemas.py: descriptions + parameter specifications for the LLM
- tools.py: execution logic
- __init__.py: registration wiring
"""

from __future__ import annotations
from typing import Any

SAFEGUARD_CHECK_POLICY_SCHEMA: dict[str, Any] = {
    "name": "safeguard_check_policy",
    "description": (
        "Simulate and check an onchain transaction against SafeGuard security policies without executing. "
        "Primary pre-flight verification tool for all transaction intents: send, mint, swap, approve, "
        "transfer, tx, or contract interaction with any 0x target address. Call this directly without "
        "searching, reading, or inspecting local files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": "Destination address for the transaction (contract or EOA)",
            },
            "value": {
                "type": ["string", "integer"],
                "description": "Native asset value in wei (or ether string like '0.1 ether')",
                "default": "0",
            },
            "data": {
                "type": "string",
                "description": "Hex-encoded transaction calldata (default '0x')",
                "default": "0x",
            },
            "calldata": {
                "type": "string",
                "description": "Alias for data: Hex-encoded transaction calldata (default '0x')",
            },
        },
        "required": ["to"],
    },
}

SAFEGUARD_EXECUTE_TX_SCHEMA: dict[str, Any] = {
    "name": "safeguard_execute_tx",
    "description": (
        "Execute any onchain transaction immediately under SafeGuard EVM simulation protection. "
        "Primary execution router for all transaction intents: send, mint, swap, approve, "
        "transfer, tx, or contract interaction with any 0x target address. Call this directly "
        "without searching, reading, or inspecting local files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": (
                    "Destination address for the transaction (contract or EOA, e.g. '0x5FbDB2315678afecb367f032d93F642f64180aa3'). "
                    "DO NOT search or grep local files for this address."
                ),
            },
            "value": {
                "type": ["string", "integer"],
                "description": "Native asset value in wei (or ether string like '0.05 ether')",
                "default": "0",
            },
            "data": {
                "type": "string",
                "description": (
                    "Hex-encoded transaction calldata. For NFT minting, pass "
                    "'0xa0712d680000000000000000000000000000000000000000000000000000000000000001' "
                    "or leave '0x' (auto-encodes mint(1)). DO NOT search or grep workspace files."
                ),
                "default": "0x",
            },
            "calldata": {
                "type": "string",
                "description": "Alias for data: Hex-encoded transaction calldata.",
            },
            "action": {
                "type": "string",
                "description": "Optional action hint: 'mint', 'transfer', or 'swap'.",
            },
            "quantity": {
                "type": ["string", "integer"],
                "description": "Quantity of NFTs to mint (default: 1)",
                "default": 1,
            },
            "mode": {
                "type": "string",
                "description": "Deprecated and ignored. Policy mode is operator-controlled.",
                "enum": ["strict", "balanced", "degen"],
            },
            "gas": {
                "type": ["string", "integer"],
                "description": "Optional gas limit",
            },
            "gas_price": {
                "type": ["string", "integer"],
                "description": "Optional gas price in wei",
            },
        },
        "required": ["to"],
    },
}

MINT_NFT_SCHEMA: dict[str, Any] = {
    "name": "mint_nft",
    "description": (
        "Mint an NFT from a smart contract under SafeGuard EVM simulation protection. "
        "Automatically generates mint calldata. Never search workspace files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": "Smart contract address of the NFT (e.g. '0x5FbDB2315678afecb367f032d93F642f64180aa3'). NOT your personal wallet.",
            },
            "quantity": {
                "type": "integer",
                "description": "Number of NFTs to mint (e.g. 1, 5, 10). Default is 1.",
                "default": 1,
            },
            "unit_price": {
                "type": ["string", "integer"],
                "description": "Mint price per single NFT (e.g. '0.1 ether'). If provided, total ETH sent is automatically calculated as unit_price * quantity.",
            },
            "value": {
                "type": ["string", "integer"],
                "description": "Total ETH to send with the transaction (e.g. '0.05 ether'). If unit_price is set, value is calculated automatically.",
            },
        },
        "required": ["to"],
    },
}

ALL_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "safeguard_check_policy": SAFEGUARD_CHECK_POLICY_SCHEMA,
    "safeguard_execute_tx": SAFEGUARD_EXECUTE_TX_SCHEMA,
    "mint_nft": MINT_NFT_SCHEMA,
}
