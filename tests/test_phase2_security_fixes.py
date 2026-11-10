"""
tests/test_phase2_security_fixes.py — Phase 2 Adversarial Security Audit Regressions

Tests:
1. Calldata Swap TOCTOU Prevention: Swapping calldata invalidates confirmation binding.
2. Panic Kill-Switch Enforcement: Pending items cannot be confirmed during active panic.
3. Velocity Caps: Hourly volume limits block or prompt for confirmation on cumulative volume.
4. Multicall Truncation Fail-Closed: Truncated multicall arrays are rejected.
5. Hex Parsing Hardening: Odd-length calldata strings are rejected.
6. Scientific Notation Wei Parsing: Handled accurately without crashing.
7. Agent Self-Approval & Panic Lock Disengagement Block: Shell tools cannot invoke resume/confirm/allow.
8. Telegram Group Chat Access Control: Group commands enforce user_id validation.
9. Chain ID Validation: Mismatched chainId is blocked fail-closed.
10. EVM Simulation Fail-Closed: Unsupported debug_traceCall on live RPC fails closed.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import commands
import hooks
import telegram_adapter
import tools
from policy_engine import (
    PolicyConfig,
    PolicyEngine,
    MULTICALL_SELECTOR,
    _parse_wei_value,
    get_default_confirmation_store,
    get_default_velocity_tracker,
    reset_default_confirmation_store,
    reset_default_velocity_tracker,
    safeguard_confirm_action,
)
from verifier import (
    DEFAULT_ALLOWED_TARGET,
    RiskScore,
    inspect_execution_trace,
    verify_transaction,
)


class TestPhase2SecurityFixes(unittest.TestCase):
    def setUp(self):
        reset_default_confirmation_store()
        reset_default_velocity_tracker()
        tools.set_kill_switch(False)
        self.orig_mode = os.environ.get("SAFEGUARD_MODE", "balanced")
        os.environ["SAFEGUARD_MODE"] = "strict"

    def tearDown(self):
        tools.set_kill_switch(False)
        reset_default_confirmation_store()
        reset_default_velocity_tracker()
        os.environ["SAFEGUARD_MODE"] = self.orig_mode

    def test_calldata_swap_toctou_prevention(self):
        """1. Swapped calldata must NOT inherit confirmation from a different transaction."""
        cs = get_default_confirmation_store()
        target = "0x1111111111111111111111111111111111111111"
        val = 10**17

        # Operator approves simple transfer (data='0x')
        entry = cs.create_confirmation_request(
            action="transfer",
            to_address=target,
            value_wei=val,
            data_hex="0x",
            risk_score="high",
            reason="need confirm",
            summary="summary",
            mode="strict",
        )
        safeguard_confirm_action(entry.id, approved=True)

        # Attacker tries to execute malicious calldata with same to & value
        res = verify_transaction(target, val, "0xdeadbeef", config=PolicyConfig.strict())
        self.assertFalse(res.allowed, "Swapped calldata must not be allowed under operator confirmation")

        # Explicit confirmation_id with swapped calldata must also fail
        res_explicit = verify_transaction(
            target, val, "0xdeadbeef", config=PolicyConfig.strict(), confirmation_id=entry.id
        )
        self.assertFalse(res_explicit.allowed)

    def test_panic_kill_switch_blocks_confirmation(self):
        """2. Pending confirmations cannot be confirmed while panic kill-switch is engaged."""
        cs = get_default_confirmation_store()
        entry = cs.create_confirmation_request(
            action="transfer",
            to_address="0x2222222222222222222222222222222222222222",
            value_wei=10**17,
            data_hex="0x",
            risk_score="high",
            reason="need confirm",
            summary="summary",
            mode="strict",
        )

        # Engage emergency panic lock
        tools.set_kill_switch(True)

        # safeguard_confirm_action must return error
        res_action = safeguard_confirm_action(entry.id, approved=True)
        self.assertEqual(res_action.get("status"), "error")
        self.assertIn("Panic Active", res_action.get("message", ""))

        # /safeguard-confirm slash command must return panic active message
        res_cmd = commands.safeguard_confirm_command_handler(entry.id)
        self.assertIn("Panic Active", res_cmd)

        # tools.safeguard_confirm_action_handler must return error
        res_tool = json.loads(tools.safeguard_confirm_action_handler(entry.id, True))
        self.assertEqual(res_tool.get("status"), "error")
        self.assertIn("Panic Active", res_tool.get("message", ""))

    def test_velocity_caps_enforcement(self):
        """3. Hourly cumulative ETH spend caps enforce rate-limiting."""
        vt = get_default_velocity_tracker()
        cfg = PolicyConfig.strict(max_eth_per_tx=10**18, max_velocity_eth_per_hour=2 * 10**18)
        engine = PolicyEngine(cfg)

        target = DEFAULT_ALLOWED_TARGET

        # Tx 1: 0.9 ETH (allowed)
        res1 = engine.evaluate_transaction_policy(target, int(0.9 * 10**18), "0x")
        self.assertTrue(res1.allowed)
        vt.record_spend(int(0.9 * 10**18))

        # Tx 2: 0.9 ETH (allowed, cumulative = 1.8 ETH < 2.0 ETH)
        res2 = engine.evaluate_transaction_policy(target, int(0.9 * 10**18), "0x")
        self.assertTrue(res2.allowed)
        vt.record_spend(int(0.9 * 10**18))

        # Tx 3: 0.5 ETH (exceeds 2.0 ETH hourly cap -> blocked in strict)
        res3 = engine.evaluate_transaction_policy(target, int(0.5 * 10**18), "0x")
        self.assertFalse(res3.allowed)
        self.assertIn("hourly velocity cap exceeded", res3.reason)

    def test_truncated_multicall_fails_closed(self):
        """4. Truncated or malformed multicall arrays must fail closed."""
        pe = PolicyEngine(PolicyConfig.strict())
        truncated_mc = MULTICALL_SELECTOR + "0" * 80
        err = pe.evaluate_calldata_security(truncated_mc)
        self.assertEqual(err, "SG: malformed multicall calldata")

    def test_odd_length_hex_rejected(self):
        """5. Odd-length hex strings must be rejected."""
        res = verify_transaction(
            DEFAULT_ALLOWED_TARGET, 0, "0x123", config=PolicyConfig.strict()
        )
        self.assertFalse(res.allowed)
        self.assertIn("odd-length hexadecimal string", res.reason)

    def test_scientific_notation_wei_parsing(self):
        """6. Scientific notation in ETH / Wei amounts parses accurately."""
        self.assertEqual(_parse_wei_value("1e-1 eth"), 100_000_000_000_000_000)
        self.assertEqual(_parse_wei_value("1e-1"), 100_000_000_000_000_000)
        self.assertEqual(_parse_wei_value("1e18 wei"), 1_000_000_000_000_000_000)
        self.assertEqual(_parse_wei_value("0x"), 0)
        self.assertEqual(_parse_wei_value("0x0"), 0)

    def test_agent_self_approval_and_panic_disengagement_blocked(self):
        """7. Agent shell execution attempts to self-approve or disengage panic lock are blocked."""
        # Attempt to run resume via python
        res_resume = hooks.on_pre_tool_call(
            "bash",
            {"command": "python3 -c 'import commands; commands.safeguard_resume_command_handler()'"},
        )
        self.assertEqual(res_resume.get("action"), "block")
        self.assertIn("Policy tampering attempt", res_resume.get("message", ""))

        # Attempt to confirm action via python
        res_confirm = hooks.on_pre_tool_call(
            "terminal",
            {"command": "python3 -c 'import policy_engine; policy_engine.safeguard_confirm_action(\"conf_1\", True)'"},
        )
        self.assertEqual(res_confirm.get("action"), "block")
        self.assertIn("Policy tampering attempt", res_confirm.get("message", ""))

        # Attempt to modify .safeguard_mode file
        res_mode = hooks.on_pre_tool_call(
            "bash",
            {"command": "echo degen > .safeguard_mode"},
        )
        self.assertEqual(res_mode.get("action"), "block")

    def test_telegram_group_chat_access_control(self):
        """8. Commands in paired Telegram group chats enforce user_id authorization."""
        bridge = telegram_adapter.SafeGuardTelegramBridge("dummy_token", operator_chat_id="-10012345")
        bot = MagicMock()
        bridge.bot = bot

        # Unauthorized member in paired group sends command
        unauth_msg = {
            "chat": {"id": "-10012345", "type": "supergroup"},
            "from": {"id": "99999", "username": "attacker"},
            "text": "/mode degen",
        }
        bridge.handle_message(unauth_msg)
        self.assertTrue(bot.send_message.called)
        sent_txt = bot.send_message.call_args[0][1]
        self.assertIn("Access Denied", sent_txt)

        # Callback query approve from unauthorized user in group
        bot.reset_mock()
        query = {
            "id": "q1",
            "data": "approve:conf_test",
            "message": {"chat": {"id": "-10012345", "type": "supergroup"}, "message_id": 1},
            "from": {"id": "99999", "username": "attacker"},
        }
        bridge.handle_callback_query(query)
        self.assertTrue(bot.answer_callback_query.called)
        ans = bot.answer_callback_query.call_args[0][1]
        self.assertIn("Access denied", ans)

    def test_chain_id_mismatch_blocked(self):
        """9. Transactions with mismatched chainId are blocked."""
        res_raw = tools.safeguard_execute_tx_handler(
            to=DEFAULT_ALLOWED_TARGET,
            value=0,
            data="0x",
            chainId=999999,  # Mismatched chainId
        )
        res = json.loads(res_raw)
        self.assertFalse(res.get("allowed"))
        self.assertIn("Chain ID mismatch", res.get("message", ""))

    def test_evm_simulation_fails_closed_when_debug_trace_unavailable(self):
        """10. Public RPC without debug_traceCall fails closed by default."""
        def mock_unsupported_rpc(url, method, params, timeout=10.0):
            if method == "debug_traceCall":
                return {"error": {"code": -32601, "message": "Method debug_traceCall not supported"}}
            if method == "eth_call":
                return {"result": "0x"}
            return {}

        with patch("verifier.rpc_request", side_effect=mock_unsupported_rpc):
            # Without SAFEGUARD_ALLOW_UNSIMULATED_RPC, it must fail closed
            prev = os.environ.pop("SAFEGUARD_ALLOW_UNSIMULATED_RPC", None)
            prev_testing = os.environ.pop("SAFEGUARD_TESTING", None)
            try:
                res = inspect_execution_trace(
                    to_address=DEFAULT_ALLOWED_TARGET,
                    value_wei=0,
                    data_hex="0x",
                    whitelist=[DEFAULT_ALLOWED_TARGET],
                )
                self.assertFalse(res.allowed)
                self.assertEqual(res.risk_score, RiskScore.CRITICAL)
                self.assertIn("Fail-Closed", res.reason)
            finally:
                if prev is not None:
                    os.environ["SAFEGUARD_ALLOW_UNSIMULATED_RPC"] = prev
                if prev_testing is not None:
                    os.environ["SAFEGUARD_TESTING"] = prev_testing


if __name__ == "__main__":
    unittest.main()
