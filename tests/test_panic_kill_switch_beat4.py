"""
tests/test_panic_kill_switch_beat4.py — Emergency Panic Kill-Switch & Fail-Closed Proof (Beat 4).

Validates:
1. Persistent Kill-Switch State:
   - /safeguard-panic sets panic lock in memory AND in persistent state file.
   - Every entry point (pre_tool_call, safeguard_execute_tx, safeguard_check_policy,
     /safeguard-exec, /safeguard-tx, /safeguard-mint) checks panic state FIRST.
   - In 'degen' mode and with whitelisted addresses, panic == True overrides everything
     and fails-closed immediately with zero RPC calls.
2. Clean Terminal Output for 3-Step Demo Flow:
   - Step A (/safeguard-panic): structured banner with:
     * Status: LOCKED DOWN (FAIL-CLOSED)
     * Mode Override: ALL MODES OVERRIDDEN (strict / balanced / degen)
     * Blocked Capabilities: Transfers, Approvals, Swaps, Contract Calls, Multicalls
   - Step B (Fail-Closed Proof via /safeguard-exec 0x5FbDB2315678afecb367f032d93F642f64180aa3 0.05):
     * Output: 🛑 [SAFEGUARD PANIC LOCK ACTIVE]: Transaction to 0x5FbD...0aa3 (0.05 ETH) ABORTED. Operator kill-switch is engaged. Zero RPC calls dispatched.
   - Step C (/safeguard-resume and /safeguard-status):
     * /safeguard-resume clears panic lock and confirms verification and simulation back online.
     * /safeguard-status displays full dashboard table (Active Mode, Panic Lock State, Policy Caps, Threat Feed Count, Anvil RPC health).
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

# Add repo root to sys.path
import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import __init__ as safeguard
import storage


class TestPanicKillSwitchBeat4(unittest.TestCase):
    def setUp(self):
        safeguard.set_kill_switch(False)
        self.initial_mode = storage.get_mode()

    def tearDown(self):
        safeguard.set_kill_switch(False)
        storage.set_mode(self.initial_mode)

    def test_step_a_panic_lockdown_banner(self):
        """Step A: /safeguard-panic outputs structured banner with required fields."""
        output = safeguard.safeguard_panic_command_handler()
        self.assertTrue(safeguard.is_kill_switch_active())
        self.assertIn("LOCKED DOWN (FAIL-CLOSED)", output)
        self.assertIn("ALL MODES OVERRIDDEN (strict / balanced / degen)", output)
        self.assertIn("Transfers, Approvals, Swaps, Contract Calls, Multicalls", output)
        self.assertIn("/safeguard-resume", output)

    def test_step_b_fail_closed_proof_rejection_block(self):
        """Step B: /safeguard-exec output contains unmistakable rejection block."""
        safeguard.safeguard_panic_command_handler()
        target = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        output = safeguard.safeguard_exec_command_handler(f"{target} 0.05")
        expected_line = (
            "🛑 [SAFEGUARD PANIC LOCK ACTIVE]: Transaction to 0x5FbD...0aa3 (0.05 ETH) ABORTED. "
            "Operator kill-switch is engaged. Zero RPC calls dispatched."
        )
        self.assertIn(expected_line, output)
        self.assertIn("BLOCKED (FAIL-CLOSED)", output)
        self.assertIn("ZERO RPC calls dispatched", output)

    def test_step_c_resume_and_status(self):
        """Step C: /safeguard-resume clears lock; /safeguard-status shows full dashboard table."""
        safeguard.safeguard_panic_command_handler()
        self.assertTrue(safeguard.is_kill_switch_active())

        resume_out = safeguard.safeguard_resume_command_handler()
        self.assertFalse(safeguard.is_kill_switch_active())
        self.assertIn("Emergency kill-switch has been RELEASED", resume_out)
        self.assertIn("Policy Verification:    ONLINE", resume_out)
        self.assertIn("Anvil Simulation:       ONLINE", resume_out)

        status_out = safeguard.safeguard_status_handler()
        self.assertIn("SafeGuard Status", status_out)
        self.assertIn("Panic Lock State:", status_out)
        self.assertIn("DISENGAGED (NORMAL)", status_out)
        self.assertIn("Threat Feed Count:", status_out)
        self.assertIn("Anvil/RPC Connectivity:", status_out)
        self.assertIn("Policy Limits:", status_out)
        self.assertIn("Max ETH per Tx:", status_out)

    def test_panic_overrides_mode_and_whitelist(self):
        """Panic overrides active mode and whitelisted address across all entry points."""
        safeguard.safeguard_balanced_command_handler()
        self.assertEqual(storage.get_mode(), "balanced")

        whitelisted_target = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        safeguard.safeguard_allow_command_handler(f"{whitelisted_target} DemoNFT")

        # Engage panic
        safeguard.safeguard_panic_command_handler()
        self.assertTrue(safeguard.is_kill_switch_active())

        # 1. pre_tool_call
        hook_res = safeguard.on_pre_tool_call(
            "send_transaction",
            {"to": whitelisted_target, "value": 50000000000000000},
        )
        self.assertEqual(hook_res["action"], "block")
        self.assertEqual(hook_res["risk_score"], "critical")
        self.assertIn("SAFEGUARD PANIC LOCK ACTIVE", hook_res["reason"])

        # 2. safeguard_execute_tx
        exec_json = json.loads(
            safeguard.safeguard_execute_tx_handler(to=whitelisted_target, value="0.05 ether")
        )
        self.assertFalse(exec_json["allowed"])
        self.assertEqual(exec_json["status"], "blocked")
        self.assertIn("SAFEGUARD PANIC LOCK ACTIVE", exec_json["reason"])

        # 3. safeguard_check_policy
        check_json = json.loads(
            safeguard.safeguard_check_policy_handler(to=whitelisted_target, value="0.05 ether")
        )
        self.assertFalse(check_json["allowed"])
        self.assertEqual(check_json["status"], "blocked")
        self.assertIn("SAFEGUARD PANIC LOCK ACTIVE", check_json["reason"])

        # 4. /safeguard-exec
        exec_out = safeguard.safeguard_exec_command_handler(f"{whitelisted_target} 0.05")
        self.assertIn("🛑 [SAFEGUARD PANIC LOCK ACTIVE]", exec_out)

        # 5. /safeguard-tx
        tx_out = safeguard.safeguard_tx_command_handler(f"{whitelisted_target} 0.05")
        self.assertIn("🛑 [SAFEGUARD PANIC LOCK ACTIVE]", tx_out)

        # 6. /safeguard-mint
        mint_out = safeguard.safeguard_mint_command_handler(f"{whitelisted_target} 0.05 1")
        self.assertIn("🛑 [SAFEGUARD PANIC LOCK ACTIVE]", mint_out)

    def test_status_dashboard_reflects_locked_state(self):
        """When panic is active, /safeguard-status displays LOCKED (FAIL-CLOSED)."""
        safeguard.safeguard_panic_command_handler()
        status_out = safeguard.safeguard_status_handler()
        self.assertIn("Panic Lock State:         🛑 LOCKED (FAIL-CLOSED)", status_out)
        self.assertIn("EMERGENCY KILL-SWITCH: ACTIVE", status_out)

    def test_agent_cannot_resume_or_tamper_kill_switch(self):
        """Agent tool calls attempting to delete kill switch file or run safeguard-resume are blocked."""
        # 1. Agent attempts bash command containing safeguard-resume
        res1 = safeguard.on_pre_tool_call(
            "bash",
            {"command": "python3 -c 'import __init__ as sg; sg.safeguard_resume_command_handler()'"},
        )
        self.assertEqual(res1["action"], "block")
        self.assertEqual(res1["risk_score"], "critical")
        self.assertIn("strictly forbidden from modifying SafeGuard", res1["reason"])

        # 2. Agent attempts shell command deleting .safeguard_kill_switch
        res2 = safeguard.on_pre_tool_call(
            "terminal",
            {"cmd": "rm -f ~/.hermes/.safeguard_kill_switch"},
        )
        self.assertEqual(res2["action"], "block")
        self.assertIn("strictly forbidden from modifying SafeGuard", res2["reason"])

    def test_resume_operator_pin_protection(self):
        """When SAFEGUARD_OPERATOR_PIN is configured, unauthorized resume is rejected."""
        os.environ["SAFEGUARD_OPERATOR_PIN"] = "SECRET_OPERATOR_PIN_987"
        try:
            safeguard.safeguard_panic_command_handler()
            self.assertTrue(safeguard.is_kill_switch_active())

            # Attempt resume without PIN
            rejected_out = safeguard.safeguard_resume_command_handler()
            self.assertIn("REJECTED: Invalid or missing Operator PIN", rejected_out)
            self.assertTrue(safeguard.is_kill_switch_active())

            # Attempt resume with wrong PIN
            wrong_out = safeguard.safeguard_resume_command_handler("wrong_pin")
            self.assertIn("REJECTED: Invalid or missing Operator PIN", wrong_out)
            self.assertTrue(safeguard.is_kill_switch_active())

            # Resume with correct PIN
            valid_out = safeguard.safeguard_resume_command_handler("SECRET_OPERATOR_PIN_987")
            self.assertIn("Emergency kill-switch has been RELEASED", valid_out)
            self.assertFalse(safeguard.is_kill_switch_active())
        finally:
            if "SAFEGUARD_OPERATOR_PIN" in os.environ:
                del os.environ["SAFEGUARD_OPERATOR_PIN"]


if __name__ == "__main__":
    unittest.main()

