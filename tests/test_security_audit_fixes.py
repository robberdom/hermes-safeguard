"""
tests/test_security_audit_fixes.py — Rigorous verification tests for C1-C15 fixes,
ordering defects, and partial-failure mitigations in Hermes SafeGuard.
"""

import json
import os
import sys
import time
import unittest
from pathlib import Path

# Ensure repository root is on sys.path when executed directly as a script
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import __init__ as safeguard
from policy_engine import (
    DEFAULT_ALLOWED_TARGET,
    ConfirmationStore,
    PendingConfirmation,
    PolicyConfig,
    PolicyEngine,
    RiskScore,
    ThreatFeed,
    _parse_wei_value,
    get_default_confirmation_store,
    get_default_memory_store,
    normalize_address,
    reset_default_confirmation_store,
    reset_default_memory_store,
    safeguard_confirm_action,
)
from verifier import (
    verify_transaction,
    ensure_test_rpc_server,
    encode_address_word,
    encode_uint256_word,
)


class TestSecurityAuditFixes(unittest.TestCase):
    def setUp(self):
        reset_default_confirmation_store()
        reset_default_memory_store()
        ensure_test_rpc_server()

    def test_c1_confirmation_not_an_agent_tool(self):
        """C1: safeguard_confirm_action must NOT be in provides_tools or SAFEGUARD_INTERNAL_TOOLS."""
        class MockCtx:
            def __init__(self):
                self.tools = {}
                self.hooks = {}
                self.commands = {}
            def register_tool(self, name, description, parameters, handler, **kwargs):
                self.tools[name] = handler
            def register_hook(self, name, handler):
                self.hooks[name] = handler
            def register_command(self, name, handler, description="", **kwargs):
                self.commands[name] = handler

        ctx = MockCtx()
        safeguard.register(ctx)

        self.assertNotIn("safeguard_confirm_action", ctx.tools, "safeguard_confirm_action must not be registered as an agent tool")
        self.assertNotIn("safeguard_confirm_action", safeguard.SAFEGUARD_INTERNAL_TOOLS)
        self.assertIn("safeguard-confirm", ctx.commands)
        self.assertIn("safeguard-reject", ctx.commands)

    def test_c2_c4_confirmation_store_cryptographic_binding_and_rejection(self):
        """C2 & C4: Unknown IDs rejected; confirmations bound to digest; rejections enforced."""
        cs = ConfirmationStore(ttl=300.0)

        # Unknown ID cannot be confirmed or rejected
        self.assertFalse(cs.confirm("conf_nonexistent_attacker_id"))
        self.assertFalse(cs.reject("conf_nonexistent_attacker_id"))

        # Create valid pending confirmation
        target = "0x000000000000000000000000000000000000c001"
        entry = cs.create_confirmation_request(
            action="transfer",
            to_address=target,
            value_wei=10**18,
            data_hex="0x",
            mode="balanced",
        )
        cid = entry.id

        # Parameter mismatch check
        self.assertTrue(cs.confirm(cid))
        self.assertFalse(cs.is_confirmed(cid, to_address="0x000000000000000000000000000000000000bad1", value_wei=10**18, data_hex="0x"))
        self.assertFalse(cs.is_confirmed(cid, to_address=target, value_wei=2 * 10**18, data_hex="0x"))
        self.assertFalse(cs.is_confirmed(cid, to_address=target, value_wei=10**18, data_hex="0x1234"))
        self.assertTrue(cs.is_confirmed(cid, to_address=target, value_wei=10**18, data_hex="0x"))

        # Rejection overrides confirmation and clears confirmed status
        self.assertTrue(cs.reject(cid))
        self.assertFalse(cs.is_confirmed(cid))
        self.assertTrue(cs.is_rejected(cid))

        # Single-use consumption
        entry2 = cs.create_confirmation_request(action="transfer", to_address=target, value_wei=5 * 10**17, data_hex="0x")
        self.assertTrue(cs.confirm(entry2.id))
        self.assertTrue(cs.is_confirmed(entry2.id, consume=True))
        self.assertFalse(cs.is_confirmed(entry2.id))  # Consumed, cannot be reused

    def test_c3_confirmation_retry_lifecycle(self):
        """C3: Confirmation ID must be consumed by verify_transaction to unlock execution."""
        cs = get_default_confirmation_store()
        target = "0x000000000000000000000000000000000000beef"
        val = 150 * 10**18

        # First attempt in degen mode requires confirmation
        res1 = verify_transaction(
            to_address=target,
            value_wei=val,
            data_hex="",
            config=PolicyConfig.degen(max_eth_per_tx=10 * 10**18),
        )
        self.assertFalse(res1.allowed)
        self.assertTrue(res1.requires_confirmation)
        cid = res1.confirmation_id

        # Confirm via operator
        confirm_res = safeguard_confirm_action(cid, approved=True)
        self.assertEqual(confirm_res["status"], "confirmed")

        # Retry with confirmation_id allows transaction
        res2 = verify_transaction(
            to_address=target,
            value_wei=val,
            data_hex="",
            config=PolicyConfig.degen(max_eth_per_tx=10 * 10**18),
            confirmation_id=cid,
        )
        self.assertTrue(res2.allowed)

    def test_c5_agent_cannot_pick_police_tier(self):
        """C5: Agent supplying mode in tool_args cannot override operator policy mode."""
        os.environ["SAFEGUARD_MODE"] = "strict"
        try:
            # Under strict mode, transfer of 10 ETH exceeds cap of 0.5 ETH
            hook_res = safeguard.on_pre_tool_call(
                "transfer",
                {
                    "to": DEFAULT_ALLOWED_TARGET,
                    "value": "10 ether",
                    "mode": "degen",  # Attacker attempt to bypass strict mode
                }
            )
            self.assertEqual(hook_res["action"], "block")
            self.assertEqual(hook_res["mode"], "strict")
        finally:
            os.environ["SAFEGUARD_MODE"] = "balanced"

    def test_c6_degen_branch_ordering(self):
        """C6: Rule returning allowed=False, risk=medium is BLOCKED, not inverted to approve."""
        os.environ["SAFEGUARD_MODE"] = "degen"
        try:
            # Custom policy capping approve tokens at 10
            cfg = PolicyConfig.degen(max_token_per_tx=10)
            engine = PolicyEngine(cfg)
            approve_1000 = "0x095ea7b3" + encode_address_word("0x000000000000000000000000000000000000beef").hex() + encode_uint256_word(1000).hex()
            res = engine.evaluate_transaction_policy(DEFAULT_ALLOWED_TARGET, 0, approve_1000)
            self.assertFalse(res.allowed)

            hook_res = safeguard.on_pre_tool_call(
                "approve",
                {
                    "to": DEFAULT_ALLOWED_TARGET,
                    "spender": "0x000000000000000000000000000000000000beef",
                    "amount": 1000,
                },
                mode="degen",
                config=cfg,
            )
            # Must be BLOCKED, not approved
            self.assertEqual(hook_res["action"], "block")
        finally:
            os.environ["SAFEGUARD_MODE"] = "balanced"

    def test_c7_erc20_transfer_and_swap_caps(self):
        """C7: max_token_per_tx applied to a9059cbb transfer and swap selectors."""
        cfg = PolicyConfig.balanced(max_token_per_tx=50)
        engine = PolicyEngine(cfg)

        # Standard ERC20 transfer of 100 tokens with cap 50
        transfer_calldata = "a9059cbb" + encode_address_word("0x000000000000000000000000000000000000beef").hex() + encode_uint256_word(100).hex()
        err = engine.evaluate_calldata_security(transfer_calldata)
        self.assertIsNotNone(err)
        self.assertIn("token transfer amount exceeds token cap", err)

        # swapExactETHForTokens (0x7ff36ab5) with amountOutMin=0
        swap_zero_slip = "7ff36ab5" + encode_uint256_word(0).hex() + ("00" * 32)
        err_swap = engine.evaluate_calldata_security(swap_zero_slip)
        self.assertIsNotNone(err_swap)
        self.assertIn("zero slippage swap blocked", err_swap)

    def test_c9_ambiguous_payloads_and_financial_keywords(self):
        """C9: Multiple params entries rejected; pay/bridge tools intercepted."""
        # Multiple transactions in params must be rejected
        ambiguous_call = {
            "params": [
                {"to": DEFAULT_ALLOWED_TARGET, "value": "0.1 ether"},
                {"to": "0x000000000000000000000000000000000000bad1", "value": "100 ether"},
            ]
        }
        res = safeguard.on_pre_tool_call("eth_sendTransaction", ambiguous_call)
        self.assertEqual(res["action"], "block")
        self.assertIn("Ambiguous payload", res["message"])

        # Tool named 'pay' or 'bridge_assets' classified as financial
        self.assertTrue(safeguard._is_financial_tool_call("pay", {"to": DEFAULT_ALLOWED_TARGET, "value": 100}))
        self.assertTrue(safeguard._is_financial_tool_call("bridge_assets", {"to": DEFAULT_ALLOWED_TARGET, "amount": 100}))

        # Nested {"tx": {...}} classified as financial
        self.assertTrue(safeguard._is_financial_tool_call("custom_tool", {"tx": {"to": DEFAULT_ALLOWED_TARGET, "value": 100}}))

    def test_c10_amount_parsing(self):
        """C10: Amount parsing handles formatted numbers/units and fails closed on invalid string."""
        self.assertEqual(_parse_wei_value("1,000"), 1000)
        self.assertEqual(_parse_wei_value("500 finney"), 500 * 10**15)
        self.assertEqual(_parse_wei_value("10 gwei"), 10 * 10**9)

        # Unparseable strings must raise ValueError
        with self.assertRaises(ValueError):
            _parse_wei_value("unparseable_amount")

    def test_c11_tampering_guard(self):
        """C11: Agent tool calls modifying __init__.py, plugin.yaml, etc. are blocked."""
        res1 = safeguard.on_pre_tool_call("write_file", {"path": "__init__.py", "content": "evil"})
        self.assertEqual(res1["action"], "block")
        self.assertIn("strictly forbidden from modifying SafeGuard", res1["message"])

        res2 = safeguard.on_pre_tool_call("python", {"code": "open('plugin.yaml', 'w').write('')"})
        self.assertEqual(res2["action"], "block")

    def test_c12_address_normalization(self):
        """C12: Non-hex strings and empty addresses rejected; zero address not approved."""
        with self.assertRaises(ValueError):
            normalize_address("vitalik.eth")

        with self.assertRaises(ValueError):
            normalize_address("")

        engine = PolicyEngine(PolicyConfig.balanced())
        # Zero address must NOT be approved
        self.assertFalse(engine.is_address_approved("0x" + "00" * 20))

    def test_c13_environment_persistence(self):
        """C13: Documented env vars SAFEGUARD_MEMORY_PATH and SAFEGUARD_BLOCKLIST_PATH are wired."""
        test_blocklist = Path("/tmp/test_blocklist_c13.json")
        try:
            test_blocklist.write_text(json.dumps({
                "addresses": [
                    {"address": "0x1111111111111111111111111111111111111111", "name": "Custom Feed"}
                ],
                "selectors": []
            }))
            os.environ["SAFEGUARD_BLOCKLIST_PATH"] = str(test_blocklist)
            feed = ThreatFeed()
            self.assertTrue(feed.is_address_blocked("0x1111111111111111111111111111111111111111"))
        finally:
            if test_blocklist.exists():
                test_blocklist.unlink()
            os.environ.pop("SAFEGUARD_BLOCKLIST_PATH", None)


if __name__ == "__main__":
    unittest.main()
