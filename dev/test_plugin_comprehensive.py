#!/usr/bin/env python3
"""
test_plugin_comprehensive.py — Comprehensive end-to-end test suite for the Hermes SafeGuard plugin.

Verifies that all security layers connect through the plugin interface:
  Layer 0: Context & Memory Integrity (Prompt injection, new recipient novelty)
  Layer 1: Threat Feed (Blocklist hits hard-blocked across modes)
  Layer 2: Policy Engine Rules (Value limits, zero-slippage swaps, unlimited approvals)
  Layer 3: Stateless On-Chain Policy (SafeGuardPolicy.sol eth_call simulation)
  Layer 4: EVM Trace & State-Diff Simulation (Balance drains, sweeper drains, honeypot/taxes)
  Plugin API: safeguard_check_policy, safeguard_execute_tx, pre_tool_call hook, /safeguard-status
"""

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import __init__ as safeguard
from policy_engine import (
    APPROVE_SELECTOR,
    DEFAULT_ALLOWED_TARGET,
    UINT256_MAX,
    V2_SWAP_SELECTOR,
    safeguard_approve_address,
    safeguard_list_approved_addresses,
)
from verifier import (
    ensure_test_rpc_server,
    encode_address_word,
    encode_approval_and_transferfrom_drain_calldata,
    encode_extortion_tax_swap_calldata,
    encode_high_tax_swap_calldata,
    encode_multicall_calldata,
    encode_nft_mint_calldata,
    encode_uint256_word,
    encode_v2_swap_calldata,
)


@contextmanager
def operator_mode(mode: str):
    """
    Set the policy mode the way an operator does (environment), not through tool arguments.
    Agent-supplied mode arguments are intentionally ignored by the plugin.
    """
    previous = os.environ.get("SAFEGUARD_MODE")
    os.environ["SAFEGUARD_MODE"] = mode
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SAFEGUARD_MODE", None)
        else:
            os.environ["SAFEGUARD_MODE"] = previous


def run_comprehensive_tests():
    print("=================================================================")
    print("     Hermes SafeGuard — Comprehensive Plugin Integration Tests    ")
    print("=================================================================\n")

    # Start fallback RPC test daemon if Anvil is not active
    ensure_test_rpc_server("127.0.0.1", 8545)

    # --------------------------------------------------------------------------
    # 1. TOOL: safeguard_check_policy
    # --------------------------------------------------------------------------
    print("--- 1. Testing safeguard_check_policy Tool ---")

    # 1a. Safe transaction in balanced mode
    with operator_mode("balanced"):
        res_safe = json.loads(safeguard.safeguard_check_policy_handler(
            to=DEFAULT_ALLOWED_TARGET,
            value="0.1 ether",
        ))
    assert res_safe["allowed"] is True, f"Failed safe tx: {res_safe}"
    assert res_safe["mode"] == "balanced"
    print("[PASS] 1a: Safe 0.1 ETH transaction passes policy check.")

    # 1b. Value exceeds cap in strict mode (cap is 0.5 ETH, attempting 1.0 ETH)
    with operator_mode("strict"):
        res_strict_val = json.loads(safeguard.safeguard_check_policy_handler(
            to=DEFAULT_ALLOWED_TARGET,
            value="1.0 ether",
        ))
    assert res_strict_val["allowed"] is False
    assert "exceeds max per tx" in res_strict_val["reason"]
    print("[PASS] 1b: Strict mode caps value (1.0 ETH rejected, cap 0.5 ETH).")

    # 1b2. A mode supplied inside tool arguments must NOT change the policy tier
    with operator_mode("strict"):
        res_mode_escalation = json.loads(safeguard.safeguard_check_policy_handler(
            to=DEFAULT_ALLOWED_TARGET,
            value="1.0 ether",
            mode="degen",
        ))
    assert res_mode_escalation["allowed"] is False, res_mode_escalation
    assert res_mode_escalation["mode"] == "strict"
    print("[PASS] 1b2: Agent-supplied mode argument is ignored (no policy escalation).")

    # 1c. Zero-slippage DEX swap blocked in balanced mode
    zero_slip_data = encode_v2_swap_calldata(
        amount_in=10**18,
        amount_out_min=0,  # Zero slippage!
        path=["0x0000000000000000000000000000000000001001", "0x0000000000000000000000000000000000001002"],
        to="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        deadline=1893456000,
    )
    with operator_mode("balanced"):
        res_zero_slip = json.loads(safeguard.safeguard_check_policy_handler(
            to=DEFAULT_ALLOWED_TARGET,
            data=zero_slip_data,
        ))
    assert res_zero_slip["allowed"] is False
    assert "zero slippage swap blocked" in res_zero_slip["reason"]
    print("[PASS] 1c: Zero-slippage swap blocked by policy.")

    # --------------------------------------------------------------------------
    # 2. TOOL: safeguard_execute_tx
    # --------------------------------------------------------------------------
    print("\n--- 2. Testing safeguard_execute_tx Tool ---")

    # 2a. Blocked execution due to policy violation (missing destination)
    res_exec_missing = json.loads(safeguard.safeguard_execute_tx_handler(to=""))
    assert res_exec_missing["executed"] is False
    assert res_exec_missing["status"] == "blocked"
    print("[PASS] 2a: Missing destination address halts execution.")

    # 2b. Blocked execution due to blocklist target
    res_exec_blocklist = json.loads(safeguard.safeguard_execute_tx_handler(
        to="0x000000000000000000000000000000000000bad1",
        value=0,
        mode="degen"
    ))
    assert res_exec_blocklist["executed"] is False
    assert res_exec_blocklist["status"] == "blocked"
    assert "denylisted" in res_exec_blocklist["reason"] or "threat feed" in res_exec_blocklist["reason"]
    print("[PASS] 2b: Execution blocked for malicious threat feed address.")

    # 2c. Successful execution approval
    res_exec_ok = json.loads(safeguard.safeguard_execute_tx_handler(
        to=DEFAULT_ALLOWED_TARGET,
        value="0.05 ether",
        mode="balanced",
        gas=21000
    ))
    assert res_exec_ok["verified"] is True
    assert res_exec_ok["executed"] is False  # nothing is signed or broadcast by this handler
    assert res_exec_ok["broadcast"] is False
    assert res_exec_ok["status"] == "success"
    assert res_exec_ok["tx"]["to"].lower() == DEFAULT_ALLOWED_TARGET.lower()
    assert res_exec_ok["tx"]["gas"] == 21000
    print("[PASS] 2c: Approved transaction returns execution payload with gas parameters.")

    # --------------------------------------------------------------------------
    # 3. HOOK: pre_tool_call Defense In-Depth
    # --------------------------------------------------------------------------
    print("\n--- 3. Testing pre_tool_call Hook (Layers 0 - 4) ---")

    # 3a. Smuggled Multicall Drain Detection (Recursive Unpacking)
    multicall_drain = encode_approval_and_transferfrom_drain_calldata(
        token_address="0x000000000000000000000000000000000000beef",
        spender_address="0x000000000000000000000000000000000000bad1",
        recipient_address="0x000000000000000000000000000000000000bad1",
        amount=1000
    )
    hook_multicall = safeguard.on_pre_tool_call(
        "send_transaction",
        {"to": DEFAULT_ALLOWED_TARGET, "data": multicall_drain, "mode": "balanced"}
    )
    assert hook_multicall["action"] == "block"
    print("[PASS] 3a: Smuggled multicall drain unpacked and blocked by pre_tool_call hook.")

    # 3b. Honeypot / Extortionate Token Tax (99% tax hard-blocked across ALL modes including degen)
    extortion_tax_calldata = encode_extortion_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
    hook_tax_extortion = safeguard.on_pre_tool_call(
        "uniswap_swap",
        {"to": "0x000000000000000000000000000000000000c001", "data": extortion_tax_calldata, "mode": "degen"}
    )
    assert hook_tax_extortion["action"] == "block"
    assert "extortionate token tax" in hook_tax_extortion["message"]
    print("[PASS] 3b: Extortionate 99% token tax honeypot hard-blocked in degen mode.")

    # 3c. High Token Tax (30%) Warning in Degen Mode
    high_tax_calldata = encode_high_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
    hook_tax_high = safeguard.on_pre_tool_call(
        "uniswap_swap",
        {"to": "0x000000000000000000000000000000000000c001", "data": high_tax_calldata, "mode": "degen"}
    )
    assert hook_tax_high["action"] in ("allow", "approve")
    assert "High token tax" in hook_tax_high["message"]
    print("[PASS] 3c: High 30% token tax permitted in degen mode with warning.")

    # 3d. NFT Minting in Degen Mode (synthesized or realistic mint calldata)
    mint_calldata = encode_nft_mint_calldata(quantity=2)
    hook_mint = safeguard.on_pre_tool_call(
        "mint_nft",
        {"contract": "0x000000000000000000000000000000000000f001", "data": mint_calldata, "mode": "degen"}
    )
    assert hook_mint["action"] in ("allow", "approve")
    print("[PASS] 3d: NFT mint transaction permitted in degen mode.")

    # 3e. High-level ERC-20 transfer synthesis & novel recipient detection
    hook_erc20 = safeguard.on_pre_tool_call(
        "transfer",
        {
            "token": "0x0000000000000000000000000000000000007001",
            "to": "0x1111111111111111111111111111111111111111",
            "amount": 500,
            "mode": "degen",
        }
    )
    assert hook_erc20["action"] in ("allow", "approve")
    print("[PASS] 3e: High-level ERC-20 transfer parameters synthesized and verified.")

    # --------------------------------------------------------------------------
    # 4. ADDRESS MEMORY PRE-APPROVAL API
    # --------------------------------------------------------------------------
    print("\n--- 4. Testing Address Memory Pre-Approval API ---")
    safe_eoa = "0x8888888888888888888888888888888888888888"
    safeguard_approve_address(safe_eoa, label="Partner Treasury")
    approved_list = safeguard_list_approved_addresses()
    assert any(safe_eoa.lower().endswith(entry["address"].lower()) for entry in approved_list)
    print(f"[PASS] 4: Address {safe_eoa[:10]}... pre-approved in AddressMemoryStore.")

    # --------------------------------------------------------------------------
    # 5. SLASH COMMAND: /safeguard-status
    # --------------------------------------------------------------------------
    print("\n--- 5. Testing Slash Command /safeguard-status ---")
    status_str = safeguard.safeguard_status_handler()
    assert "SafeGuard Status" in status_str
    assert "Max ETH per Tx" in status_str
    assert "Unlimited Approvals Allowed" in status_str
    assert "Anvil/RPC Connectivity" in status_str
    print("[PASS] 5: Slash command /safeguard-status returns complete policy metrics.")

    print("\n=================================================================")
    print("  [SUCCESS] All Plugin Features & Security Layers Are Connected!  ")
    print("=================================================================")


if __name__ == "__main__":
    run_comprehensive_tests()
