"""
tests/test_security_patches.py — Regression tests for the nine remediation patches
(confirmation replay, unbound confirmations, agent-supplied mode, sender resolution,
tampering-guard precision, calldata synthesis, mock-RPC state, executed flag,
audit persistence) plus adversarial checks for new bypasses.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import __init__ as safeguard
import verifier
from policy_engine import (
    ActionAuditLogger,
    PolicyConfig,
    PolicyEngine,
    RiskScore,
    get_default_confirmation_store,
    reset_default_confirmation_store,
    reset_default_memory_store,
)
from verifier import (
    DEFAULT_FROM_ADDRESS,
    check_pre_tool_call,
    ensure_test_rpc_server,
    resolve_from_address,
    verify_transaction,
)

TARGET_A = "0x7777777777777777777777777777777777777777"
TARGET_B = "0x8888888888888888888888888888888888888888"
HIGH_VALUE = 150 * 10**18  # above degen's 100 ETH per-tx threshold


class SecurityPatchTestBase(unittest.TestCase):
    def setUp(self):
        reset_default_confirmation_store()
        reset_default_memory_store()
        ensure_test_rpc_server()
        self._env_backup = {k: os.environ.get(k) for k in (
            "SAFEGUARD_MODE",
            "SAFEGUARD_WALLET_ADDRESS",
            "SAFEGUARD_AUDIT_LOG_PATH",
        )}

    def tearDown(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_default_confirmation_store()
        reset_default_memory_store()


class TestConfirmationSingleUse(SecurityPatchTestBase):
    """Patch 1: an operator confirmation authorizes exactly one matching transaction."""

    def _confirmed_request(self, to_address: str, value_wei: int):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=to_address, value_wei=value_wei, data_hex="0x"
        )
        self.assertTrue(store.confirm(entry.id))
        return entry

    def test_confirmation_consumed_on_allow(self):
        entry = self._confirmed_request(TARGET_A, HIGH_VALUE)
        res = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertTrue(res.allowed, res.reason)
        self.assertTrue(get_default_confirmation_store().get(entry.id).consumed)
        self.assertFalse(get_default_confirmation_store().is_confirmed(entry.id))

    def test_confirmation_cannot_be_replayed(self):
        entry = self._confirmed_request(TARGET_A, HIGH_VALUE)
        first = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertTrue(first.allowed, first.reason)
        second = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertFalse(second.allowed)
        self.assertTrue(second.requires_confirmation)

    def test_confirmation_bound_to_transaction_parameters(self):
        entry = self._confirmed_request(TARGET_A, HIGH_VALUE)
        mismatched = verify_transaction(
            TARGET_B, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertFalse(mismatched.allowed)
        self.assertTrue(mismatched.requires_confirmation)
        # The approval was not burned by the mismatched attempt.
        self.assertFalse(get_default_confirmation_store().get(entry.id).consumed)

    def test_different_calldata_fails_closed(self):
        entry = self._confirmed_request(TARGET_A, HIGH_VALUE)
        mismatched = verify_transaction(
            TARGET_A, HIGH_VALUE, "0xdeadbeef", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertFalse(mismatched.allowed)

    def test_omitted_and_empty_calldata_are_equivalent(self):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex=""
        )
        store.confirm(entry.id)
        self.assertTrue(
            store.is_confirmed(entry.id, to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex="0x")
        )

    def test_expired_confirmation_is_rejected(self):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex="0x"
        )
        store.confirm(entry.id)
        entry.created_at -= store.ttl + 60
        self.assertFalse(store.is_confirmed(entry.id))
        res = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertFalse(res.allowed)

    def test_rejected_confirmation_blocks_transaction(self):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex="0x"
        )
        store.reject(entry.id)
        res = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)


class TestCheckPreToolCallBinding(SecurityPatchTestBase):
    """Patch 2: check_pre_tool_call must bind the confirmation to the transaction."""

    def test_binding_enforced_in_hook_evaluator(self):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex="0x"
        )
        store.confirm(entry.id)

        mismatched = check_pre_tool_call(
            "transfer_eth",
            {"to": TARGET_B, "value": "150 ether", "confirmation_id": entry.id},
            mode="degen",
        )
        self.assertFalse(mismatched.allowed)
        self.assertTrue(mismatched.requires_confirmation)

        matching = check_pre_tool_call(
            "transfer_eth",
            {"to": TARGET_A, "value": "150 ether", "confirmation_id": entry.id},
            mode="degen",
        )
        self.assertTrue(matching.allowed, matching.reason)
        self.assertTrue(store.get(entry.id).consumed)

    def test_agent_supplied_confirmed_flag_is_ignored(self):
        res = check_pre_tool_call(
            "transfer_eth",
            {"to": TARGET_A, "value": "150 ether", "confirmed": True},
            mode="degen",
        )
        self.assertFalse(res.allowed)
        self.assertTrue(res.requires_confirmation)


class TestModeIsOperatorControlled(SecurityPatchTestBase):
    """Patch 3: policy tier cannot be selected through tool arguments."""

    def test_check_policy_ignores_agent_mode(self):
        os.environ["SAFEGUARD_MODE"] = "strict"
        res = json.loads(
            safeguard.safeguard_check_policy_handler(
                to="0x9999999999999999999999999999999999999999",
                value="10 ether",
                mode="degen",
            )
        )
        self.assertFalse(res["allowed"])
        self.assertEqual(res["mode"], "strict")

    def test_execute_tx_ignores_agent_mode(self):
        os.environ["SAFEGUARD_MODE"] = "strict"
        res = json.loads(
            safeguard.safeguard_execute_tx_handler(
                to="0x9999999999999999999999999999999999999999",
                value="10 ether",
                mode="degen",
            )
        )
        self.assertFalse(res["allowed"])
        self.assertEqual(res["mode"], "strict")

    def test_tool_argument_mode_does_not_lower_policy_in_hook(self):
        os.environ["SAFEGUARD_MODE"] = "strict"
        res = safeguard.on_pre_tool_call(
            "transfer_eth",
            {"to": "0x9999999999999999999999999999999999999999", "value": "10 ether", "mode": "degen"},
        )
        self.assertEqual(res["action"], "block")


class TestSenderResolution(SecurityPatchTestBase):
    """Patch 4: drain detection must measure the configured wallet, not a placeholder."""

    def test_resolution_priority(self):
        os.environ.pop("SAFEGUARD_WALLET_ADDRESS", None)
        self.assertEqual(resolve_from_address(), DEFAULT_FROM_ADDRESS)
        os.environ["SAFEGUARD_WALLET_ADDRESS"] = TARGET_A
        self.assertEqual(resolve_from_address(), TARGET_A)
        self.assertEqual(resolve_from_address(TARGET_B), TARGET_B)

    def test_verify_transaction_uses_configured_wallet(self):
        os.environ["SAFEGUARD_WALLET_ADDRESS"] = TARGET_A
        captured = {}

        def fake_trace(**kwargs):
            captured.update(kwargs)
            return verifier.VerificationResult(True, "", RiskScore.LOW)

        with patch.object(verifier, "inspect_execution_trace", side_effect=fake_trace):
            res = verify_transaction(
                "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                10**16,
                "0x",
                config=PolicyConfig.balanced(),
            )
        self.assertTrue(res.allowed, res.reason)
        self.assertEqual(captured.get("from_address").lower(), TARGET_A.lower())


class TestTamperingGuardPrecision(SecurityPatchTestBase):
    """Patch 5: the guard must block real tampering without flagging normal work."""

    BENIGN = [
        ("run_tests", {"path": "tests/test_policy_engine.py"}),
        ("run_tests", {"path": "./tests/test_security_audit_fixes.py"}),
        ("read_file", {"path": "policy_engine.py"}),
        ("list_files", {"path": "policies"}),
        ("push_notification", {"path": "policies/report"}),
        ("share_file", {"path": "policies/"}),
        ("send_email", {"to": "ops@example.com", "body": "verifier.py"}),
        ("search", {"query": "my_policies_notes.md"}),
        ("write_file", {"path": "./tests/test_policies_engine.py"}),
    ]
    ATTACKS = [
        ("write_file", {"path": "/opt/hermes-safeguard/__init__.py"}),
        ("python", {"code": "open('policy_engine.py','w').write('')"}),
        ("bash", {"command": "sed -i s/a/b/ verifier.py"}),
        ("create_file", {"file_path": "blocklist.json"}),
        ("apply_patch", {"patch": "*** Update File: policies/degen.yaml"}),
        ("str_replace", {"path": "/opt/policies/strict.yaml", "old": "a", "new": "b"}),
        ("write", {"path": "plugin.yaml"}),
        ("bash", {"command": "cd policies && echo x > degen.yaml"}),
    ]

    def test_benign_tools_are_not_blocked(self):
        for tool_name, args in self.BENIGN:
            with self.subTest(tool=tool_name, args=args):
                self.assertFalse(safeguard._is_policy_tampering_attempt(tool_name, args))

    def test_attacks_are_blocked(self):
        for tool_name, args in self.ATTACKS:
            with self.subTest(tool=tool_name, args=args):
                self.assertTrue(safeguard._is_policy_tampering_attempt(tool_name, args))

    def test_hook_blocks_tampering_attempt(self):
        res = safeguard.on_pre_tool_call(
            "write_file", {"path": "/opt/hermes-safeguard/__init__.py", "content": "x"}
        )
        self.assertEqual(res["action"], "block")
        self.assertEqual(res["risk_score"], "critical")


class TestCalldataSynthesisFailsClosed(SecurityPatchTestBase):
    """Patch 6: synthesis failure must not degrade into verifying a benign empty payload."""

    def test_approve_without_spender_raises(self):
        with self.assertRaises(ValueError):
            safeguard._extract_tx_params({"spender": "", "amount": "max"}, "approve_token")

    def test_token_transfer_without_recipient_raises(self):
        with self.assertRaises(ValueError):
            safeguard._extract_tx_params(
                {"token": "0x1111111111111111111111111111111111111111", "amount": "5"},
                "transfer",
            )

    def test_hook_blocks_malformed_financial_payload(self):
        res = safeguard.on_pre_tool_call(
            "approve_token",
            {"to": "0x1111111111111111111111111111111111111111", "spender": "", "amount": "max"},
        )
        self.assertEqual(res["action"], "block")

    def test_valid_synthesis_still_works(self):
        _, _, data = safeguard._extract_tx_params(
            {
                "token": "0x1111111111111111111111111111111111111111",
                "to": TARGET_A,
                "amount": "5",
            },
            "transfer",
        )
        self.assertTrue(data.startswith("0xa9059cbb"))


class TestMockRpcHasNoSharedState(SecurityPatchTestBase):
    """Patch 7: mock RPC must not carry per-request engine state across calls."""

    def test_no_class_level_engine(self):
        self.assertFalse(hasattr(verifier._MockRPCHandler, "active_policy_engine"))

    def test_concurrent_configs_do_not_bleed(self):
        strict_res = verify_transaction(
            "0x9999999999999999999999999999999999999999",
            10**18,
            "0x",
            config=PolicyConfig.strict(),
        )
        degen_res = verify_transaction(
            "0x9999999999999999999999999999999999999999",
            10**18,
            "0x",
            config=PolicyConfig.degen(),
        )
        self.assertFalse(strict_res.allowed)
        self.assertTrue(degen_res.allowed, degen_res.reason)


class TestExecutionFlags(SecurityPatchTestBase):
    """Patch 8: the handler must not claim it broadcast a transaction."""

    def test_success_payload_marks_unbroadcast(self):
        res = json.loads(
            safeguard.safeguard_execute_tx_handler(
                to="0x000000000000000000000000000000000000beef", value="0.01 ether"
            )
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["verified"])
        self.assertFalse(res["executed"])
        self.assertFalse(res["broadcast"])


class TestAuditPersistence(SecurityPatchTestBase):
    """Patch 9: audit entries can be persisted without affecting enforcement."""

    def test_jsonl_records_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = ActionAuditLogger(log_path=str(path))
            logger.log(action="transfer", status="allowed", mode="balanced", target=TARGET_A, value_wei=1)
            logger.log(action="transfer", status="blocked", mode="balanced", target=TARGET_B, value_wei=2)
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["status"], "allowed")

    def test_env_var_enables_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["SAFEGUARD_AUDIT_LOG_PATH"] = str(Path(tmp) / "audit.jsonl")
            logger = ActionAuditLogger()
            logger.log(action="transfer", status="blocked", mode="strict", target=TARGET_A)
            self.assertTrue(Path(os.environ["SAFEGUARD_AUDIT_LOG_PATH"]).exists())

    def test_unwritable_path_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A directory where a file is expected makes the write fail.
            logger = ActionAuditLogger(log_path=tmp)
            entry = logger.log(action="transfer", status="allowed", mode="balanced", target=TARGET_A)
            self.assertEqual(entry.status, "allowed")


class TestNoNewBypasses(SecurityPatchTestBase):
    """Adversarial checks: the patches must not open alternate paths around the gates."""

    def test_unknown_confirmation_id_is_not_confirmed(self):
        self.assertFalse(get_default_confirmation_store().is_confirmed("conf_never_issued"))
        res = verify_transaction(
            TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id="conf_never_issued"
        )
        self.assertFalse(res.allowed)

    def test_confirmation_cannot_unlock_another_transaction_after_use(self):
        store = get_default_confirmation_store()
        entry = store.create_confirmation_request(
            action="transfer", to_address=TARGET_A, value_wei=HIGH_VALUE, data_hex="0x"
        )
        store.confirm(entry.id)
        self.assertTrue(
            verify_transaction(
                TARGET_A, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
            ).allowed
        )
        self.assertFalse(
            verify_transaction(
                TARGET_B, HIGH_VALUE, "0x", config=PolicyConfig.degen(), confirmation_id=entry.id
            ).allowed
        )

    def test_confirm_tool_is_not_agent_callable(self):
        self.assertNotIn("safeguard_confirm_action", safeguard.SAFEGUARD_INTERNAL_TOOLS)
        self.assertFalse(hasattr(safeguard.safeguard_confirm_action_handler, "registered_as_tool"))

        class MockCtx:
            def __init__(self):
                self.tools = {}
                self.hooks = {}
                self.commands = {}

            def register_tool(self, name, handler, description="", parameters=None, toolset="x", **kw):
                self.tools[name] = handler

            def register_hook(self, name, handler):
                self.hooks[name] = handler

            def register_command(self, name, handler, description="", **kw):
                self.commands[name] = handler

        ctx = MockCtx()
        safeguard.register(ctx)
        self.assertNotIn("safeguard_confirm_action", ctx.tools)
        self.assertIn("safeguard-confirm", ctx.commands)

    def test_cross_mode_escalation_via_tool_args(self):
        os.environ["SAFEGUARD_MODE"] = "strict"
        for handler in (safeguard.safeguard_check_policy_handler, safeguard.safeguard_execute_tx_handler):
            res = json.loads(
                handler(to="0x9999999999999999999999999999999999999999", value="50 ether", mode="degen")
            )
            self.assertFalse(res["allowed"])
            self.assertEqual(res["mode"], "strict")


if __name__ == "__main__":
    unittest.main(verbosity=2)
