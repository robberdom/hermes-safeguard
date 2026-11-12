#!/usr/bin/env python3
"""
tests/test_slash_commands.py — Comprehensive tests for Hermes SafeGuard slash commands.

Verifies:
  1. /safeguard-mode: cycling (strict -> balanced -> degen -> strict), direct switching,
     shortcuts (/safeguard-strict, /safeguard-balanced, /safeguard-degen), and typo aliases.
  2. /safeguard-status: metrics display and backward compatibility.
  3. /safeguard-pending: listing held confirmation items and empty state.
  4. /safeguard-confirm and /safeguard-reject: approval/rejection workflows and error messages.
  5. /safeguard-whitelist, /safeguard-allow, /safeguard-revoke: address memory management.
  6. /safeguard-check: inspecting clean, approved, and malicious threat feed addresses.
  7. /safeguard-threats: threat intelligence stats display.
  8. /safeguard-audit: audit log retrieval and formatting.
  9. /safeguard-help: command manual and active mode display.
 10. PluginContext registration: all commands and system prompt section registered.
"""

import os
import unittest
from typing import Any, Callable

import __init__ as safeguard
from policy_engine import (
    AddressMemoryStore,
    ConfirmationStore,
    get_default_audit_logger,
    get_default_confirmation_store,
    get_default_memory_store,
    get_default_threat_feed,
    reset_default_confirmation_store,
    reset_default_memory_store,
)


class MockHermesContext:
    """Mock representing Hermes Agent PluginContext."""

    def __init__(self):
        self.tools: dict[str, Any] = {}
        self.hooks: dict[str, Callable] = {}
        self.commands: dict[str, Callable] = {}
        self.system_prompts: dict[str, Any] = {}

    def register_tool(self, name: str, toolset: str, schema: dict, handler: Callable, **kwargs):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_hook(self, name: str, handler: Callable):
        self.hooks[name] = handler

    def register_command(self, name: str, handler: Callable, description: str = "", **kwargs):
        self.commands[name] = handler

    def register_system_prompt_section(self, name: str, content: str, position: str = "", **kwargs):
        self.system_prompts[name] = {"content": content, "position": position}


class TestSafeGuardSlashCommands(unittest.TestCase):
    def setUp(self):
        self._orig_env_mode = os.environ.get("SAFEGUARD_MODE")
        self._mode_file = safeguard.Path(__file__).resolve().parent.parent / ".safeguard_mode"
        self._orig_file_mode = self._mode_file.read_text(encoding="utf-8") if self._mode_file.is_file() else None
        self._env_file = safeguard.Path(__file__).resolve().parent.parent / ".env"
        self._orig_env_content = self._env_file.read_text(encoding="utf-8") if self._env_file.is_file() else None
        os.environ["SAFEGUARD_MODE"] = "balanced"
        if "SAFEGUARD_POLICY_PATH" in os.environ:
            del os.environ["SAFEGUARD_POLICY_PATH"]
        reset_default_confirmation_store()
        reset_default_memory_store()

    def tearDown(self):
        if self._orig_env_mode is not None:
            os.environ["SAFEGUARD_MODE"] = self._orig_env_mode
        elif "SAFEGUARD_MODE" in os.environ:
            del os.environ["SAFEGUARD_MODE"]
        if self._orig_file_mode is not None:
            self._mode_file.write_text(self._orig_file_mode, encoding="utf-8")
        elif self._mode_file.is_file():
            self._mode_file.unlink(missing_ok=True)
        if self._orig_env_content is not None:
            self._env_file.write_text(self._orig_env_content, encoding="utf-8")
        if "SAFEGUARD_POLICY_PATH" in os.environ:
            del os.environ["SAFEGUARD_POLICY_PATH"]
        reset_default_confirmation_store()
        reset_default_memory_store()

    # --------------------------------------------------------------------------
    # 1. Mode Cycling & Switching
    # --------------------------------------------------------------------------

    def test_mode_cycling_strict_balanced(self):
        """Typing /safeguard-mode with no args cycles between strict and balanced."""
        # Start at strict
        safeguard.safeguard_mode_command_handler("strict")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")

        # 1st cycle: strict -> balanced
        res1 = safeguard.safeguard_mode_command_handler()
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "balanced")
        self.assertIn("BALANCED", res1)

        # 2nd cycle: balanced -> strict
        res2 = safeguard.safeguard_mode_command_handler()
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")
        self.assertIn("STRICT", res2)

    def test_mode_direct_switching(self):
        """Setting mode directly via /safeguard-mode <strict|balanced>."""
        res_strict = safeguard.safeguard_mode_command_handler("strict")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")
        self.assertIn("STRICT", res_strict)
        self.assertIn("0.50 ETH", res_strict)

        res_balanced = safeguard.safeguard_mode_command_handler("balanced")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "balanced")
        self.assertIn("BALANCED", res_balanced)
        self.assertIn("5.00 ETH", res_balanced)

    def test_mode_conversational_and_number_arguments(self):
        """Handles conversational text and 1/2 numbers gracefully."""
        # Conversational text like "switch to strict mode"
        safeguard.safeguard_mode_command_handler("switch to strict mode")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")

        # Numeric map: 1=strict, 2=balanced
        safeguard.safeguard_mode_command_handler("1")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")

        safeguard.safeguard_mode_command_handler("2")
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "balanced")

    def test_mode_unknown_argument(self):
        """Unknown mode argument displays error and helpful syntax instructions."""
        res = safeguard.safeguard_mode_command_handler("super_ultra_mode")
        self.assertIn("Unknown mode", res)
        self.assertIn("Valid modes: strict (1), balanced (2)", res)

    def test_mode_shortcut_commands(self):
        """Direct shortcut commands /safeguard-strict, /safeguard-balanced."""
        safeguard.safeguard_strict_command_handler()
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "strict")

        safeguard.safeguard_balanced_command_handler()
        self.assertEqual(os.environ["SAFEGUARD_MODE"], "balanced")

    # --------------------------------------------------------------------------
    # 2. Status Command
    # --------------------------------------------------------------------------

    def test_status_command(self):
        """Status command output contains all required health metrics."""
        os.environ["SAFEGUARD_MODE"] = "strict"
        output = safeguard.safeguard_status_handler()
        self.assertIn("SafeGuard Status", output)
        self.assertIn("Mode: strict", output)
        self.assertIn("Max ETH per Tx", output)
        self.assertIn("Unlimited Approvals Allowed", output)
        self.assertIn("Anvil/RPC Connectivity", output)

    # --------------------------------------------------------------------------
    # 3. Pending Confirmations & Confirm/Reject Commands
    # --------------------------------------------------------------------------

    def test_pending_command_empty(self):
        """When no confirmations are pending, shows clean message."""
        output = safeguard.safeguard_pending_command_handler()
        self.assertIn("No pending transactions awaiting confirmation", output)

    def test_pending_and_confirm_reject_workflow(self):
        """Full lifecycle: create pending confirmation -> list -> confirm -> reject."""
        cs = get_default_confirmation_store()
        entry1 = cs.create_confirmation_request(
            action="transfer",
            to_address="0x1111111111111111111111111111111111111111",
            value_wei=10**18,
            data_hex="0x",
            risk_score="high",
            reason="Strict mode new recipient",
            summary="Transfer 1.0 ETH to new recipient",
            mode="strict",
        )
        entry2 = cs.create_confirmation_request(
            action="transfer",
            to_address="0x2222222222222222222222222222222222222222",
            value_wei=2 * 10**18,
            data_hex="0x",
            risk_score="high",
            reason="Large transfer",
            summary="Transfer 2.0 ETH",
            mode="strict",
        )

        # Verify /safeguard-pending lists both
        list_output = safeguard.safeguard_pending_command_handler()
        self.assertIn(entry1.id, list_output)
        self.assertIn(entry2.id, list_output)
        self.assertIn("0x1111111111111111111111111111111111111111", list_output)

        # Confirm entry1
        conf_res = safeguard.safeguard_confirm_command_handler(entry1.id)
        self.assertIn("CONFIRMED", conf_res)
        self.assertTrue(cs.is_confirmed(entry1.id))

        # Reject entry2
        rej_res = safeguard.safeguard_reject_command_handler(entry2.id)
        self.assertIn("REJECTED", rej_res)
        self.assertTrue(cs.is_rejected(entry2.id))

        # Pending list should now be empty
        empty_output = safeguard.safeguard_pending_command_handler()
        self.assertIn("No pending transactions awaiting confirmation", empty_output)

    def test_confirm_reject_missing_id_guidance(self):
        """Calling /safeguard-confirm or /safeguard-reject without ID gives helpful instructions."""
        conf_msg = safeguard.safeguard_confirm_command_handler()
        self.assertIn("Usage: /safeguard-confirm <confirmation_id>", conf_msg)
        self.assertIn("/safeguard-pending", conf_msg)

        rej_msg = safeguard.safeguard_reject_command_handler()
        self.assertIn("Usage: /safeguard-reject <confirmation_id>", rej_msg)

    # --------------------------------------------------------------------------
    # 4. Whitelist & Memory Management Commands
    # --------------------------------------------------------------------------

    def test_whitelist_allow_and_revoke(self):
        """Test pre-approving, viewing, and revoking addresses in memory store."""
        target_addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        # Initially empty
        wl_empty = safeguard.safeguard_whitelist_command_handler()
        self.assertIn("No pre-approved addresses", wl_empty)

        # Allow address
        allow_res = safeguard.safeguard_allow_command_handler(f"{target_addr} Vitalik Treasury")
        self.assertIn("Pre-approved address", allow_res)
        self.assertIn(target_addr.lower(), allow_res.lower())

        # Whitelist now shows it
        wl_listed = safeguard.safeguard_whitelist_command_handler()
        self.assertIn("Vitalik Treasury", wl_listed)
        self.assertIn(target_addr.lower()[2:], wl_listed.lower())

        # Revoke address
        revoke_res = safeguard.safeguard_revoke_command_handler(target_addr)
        self.assertIn("Revoked approval", revoke_res)

        # Whitelist empty again
        wl_after = safeguard.safeguard_whitelist_command_handler()
        self.assertIn("No pre-approved addresses", wl_after)

    def test_allow_blocked_threat_address_fails_safe(self):
        """Cannot pre-approve a known malicious threat address."""
        # Simulated Drain Exploit Contract from blocklist.json
        drainer_addr = "0x000000000000000000000000000000000000bad1"
        res = safeguard.safeguard_allow_command_handler(drainer_addr)
        self.assertIn("Failed to approve", res)
        self.assertIn("threat feed", res.lower())

    # --------------------------------------------------------------------------
    # 5. Check & Threat Intelligence Commands
    # --------------------------------------------------------------------------

    def test_check_clean_and_malicious_addresses(self):
        """Testing /safeguard-check on clean, approved, and malicious addresses."""
        clean_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        clean_res = safeguard.safeguard_check_command_handler(clean_addr)
        self.assertIn("Clean", clean_res)

        # Malicious address
        drainer_addr = "0x000000000000000000000000000000000000bad1"
        threat_res = safeguard.safeguard_check_command_handler(drainer_addr)
        self.assertIn("BLOCKED", threat_res)
        self.assertIn("Simulated Drain Exploit Contract", threat_res)

    def test_threats_command(self):
        """Testing /safeguard-threats returns feed status."""
        summary = safeguard.safeguard_threats_command_handler()
        self.assertIn("SafeGuard Threat Intelligence Status", summary)
        self.assertIn("Blocked Threat Addresses", summary)
        self.assertIn("Blocked Calldata Selectors", summary)

    # --------------------------------------------------------------------------
    # 6. Audit & Help Commands
    # --------------------------------------------------------------------------

    def test_audit_command(self):
        """Testing /safeguard-audit returns recent logs."""
        logger = get_default_audit_logger()
        logger.log(
            action="transfer",
            status="allowed",
            mode="strict",
            target="0x3333333333333333333333333333333333333333",
            value_wei=10**17,
            risk_score="low",
            reason="Safe transaction",
        )
        audit_res = safeguard.safeguard_audit_command_handler("5")
        self.assertIn("SafeGuard Audit Log", audit_res)
        self.assertIn("ALLOWED", audit_res)

    def test_help_command(self):
        """Testing /safeguard-help output."""
        help_text = safeguard.safeguard_help_command_handler()
        self.assertIn("Hermes SafeGuard Slash Commands Reference", help_text)
        self.assertIn("/safeguard-mode", help_text)
        self.assertIn("/safeguard-status", help_text)
        self.assertIn("/safeguard-pending", help_text)
        self.assertIn("/safeguard-confirm", help_text)
        self.assertIn("/safeguard-whitelist", help_text)

    # --------------------------------------------------------------------------
    # 7. Emergency Kill-Switch & Alert / Sync Commands
    # --------------------------------------------------------------------------

    def test_panic_and_resume_kill_switch(self):
        """Testing /safeguard-panic engages emergency kill-switch and /safeguard-resume releases it."""
        # 1. Engage emergency panic
        panic_msg = safeguard.safeguard_panic_command_handler()
        self.assertIn("EMERGENCY KILL-SWITCH ENGAGED", panic_msg)
        self.assertTrue(safeguard.is_kill_switch_active())

        # 2. Verify status reflects active lockdown
        status_msg = safeguard.safeguard_status_handler()
        self.assertIn("EMERGENCY KILL-SWITCH: ACTIVE", status_msg)

        # 3. Verify pre_tool_call hard-blocks transactions across all modes (even degen!)
        os.environ["SAFEGUARD_MODE"] = "degen"
        hook_res = safeguard.on_pre_tool_call(
            "send_transaction",
            {"to": "0x1111111111111111111111111111111111111111", "value": 10**17},
        )
        self.assertEqual(hook_res["action"], "block")
        self.assertEqual(hook_res["risk_score"], "critical")
        self.assertIn("Emergency kill-switch is ACTIVE", hook_res["reason"])

        # 4. Verify safeguard_execute_tx tool is halted
        exec_res = safeguard.safeguard_execute_tx_handler(
            to="0x1111111111111111111111111111111111111111",
            value="0.1 ether",
        )
        import json
        exec_data = json.loads(exec_res)
        self.assertFalse(exec_data["allowed"])
        self.assertIn("Emergency kill-switch is ACTIVE", exec_data["reason"])

        # 5. Release emergency lockdown
        resume_msg = safeguard.safeguard_resume_command_handler()
        self.assertIn("Emergency kill-switch has been RELEASED", resume_msg)
        self.assertFalse(safeguard.is_kill_switch_active())

    def test_sync_threat_feed_command(self):
        """Testing /safeguard-sync forces threat intelligence cache reload."""
        sync_res = safeguard.safeguard_sync_command_handler()
        self.assertIn("Threat Intelligence Sync Complete", sync_res)
        self.assertIn("Blocked Threat Addresses", sync_res)
        self.assertIn("ACTIVE & UP TO DATE", sync_res)

    def test_test_alert_command_unconfigured_and_simulated(self):
        """Testing /safeguard-test-alert when credentials are unconfigured."""
        # Ensure clean environment
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SAFEGUARD_WEBHOOK_URL"):
            if k in os.environ:
                del os.environ[k]

        alert_output = safeguard.safeguard_test_alert_command_handler()
        self.assertIn("Alert Delivery Unconfigured", alert_output)
        self.assertIn("TELEGRAM_BOT_TOKEN", alert_output)
        self.assertIn("Simulated alert preview", alert_output)

    # --------------------------------------------------------------------------
    # 8. Plugin Registration Integration
    # --------------------------------------------------------------------------

    def test_plugin_registration_wires_all_slash_commands(self):
        """register(ctx) registers all slash commands, typo aliases, and system prompt."""
        ctx = MockHermesContext()
        safeguard.register(ctx)

        # Core mode commands
        self.assertIn("safeguard-mode", ctx.commands)
        self.assertIn("safeguard-strict", ctx.commands)
        self.assertIn("safeguard-balanced", ctx.commands)
        self.assertIn("safeguard-degen", ctx.commands)

        # Status, threat intelligence & emergency controls
        self.assertIn("safeguard-status", ctx.commands)
        self.assertIn("safeguard-help", ctx.commands)
        self.assertIn("safeguard", ctx.commands)
        self.assertIn("safeguard-threats", ctx.commands)
        self.assertIn("safeguard-sync", ctx.commands)
        self.assertIn("safeguard-test-alert", ctx.commands)
        self.assertIn("safeguard-panic", ctx.commands)
        self.assertIn("safeguard-resume", ctx.commands)
        self.assertIn("safeguard-audit", ctx.commands)

        # Confirmations
        self.assertIn("safeguard-pending", ctx.commands)
        self.assertIn("safeguard-confirm", ctx.commands)
        self.assertIn("safeguard-reject", ctx.commands)

        # Whitelist & addresses
        self.assertIn("safeguard-whitelist", ctx.commands)
        self.assertIn("safeguard-allow", ctx.commands)
        self.assertIn("safeguard-revoke", ctx.commands)
        self.assertIn("safeguard-check", ctx.commands)

        # Typo alias
        self.assertIn("safegaurd-mode", ctx.commands)
        self.assertIn("safegaurd-status", ctx.commands)
        self.assertIn("safegaurd-panic", ctx.commands)
        self.assertIn("safegaurd-resume", ctx.commands)

        # System prompt section registered
        self.assertIn("safeguard.guidelines", ctx.system_prompts)
        self.assertIn("/safeguard-mode", ctx.system_prompts["safeguard.guidelines"]["content"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
