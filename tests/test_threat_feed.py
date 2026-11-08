"""
test_threat_feed.py — Unit and integration tests for Hermes SafeGuard Threat Feed & Blocklist.

Tests:
  - Local blocklist loading (JSON/YAML) and updating
  - Threat feed checks blocking known malicious contracts in strict, balanced, and degen modes
  - Threat feed checks blocking known phishing/drain addresses across all modes
  - Hard-blocking invariant in degen mode (even with human confirmation)
  - Dangerous function selector blocking (direct and smuggled inside multicall)
  - Pre-tool-call hook blocking interactions with listed threat targets
  - Pre-approval rejection: cannot approve addresses listed on threat feed
  - Tool/function `safeguard_search_threat_reports` / `search_threat_reports` query capabilities
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from policy_engine import (
    DEFAULT_ALLOWED_TARGET,
    MULTICALL_SELECTOR,
    TRANSFER_FROM_SELECTOR,
    PolicyConfig,
    PolicyEngine,
    RiskScore,
    ThreatEntry,
    ThreatFeed,
    check_pre_tool_call,
    get_default_threat_feed,
    normalize_address,
    safeguard_approve_address,
    safeguard_search_threat_reports,
    search_threat_reports,
)
from verifier import (
    encode_address_word,
    encode_multicall_calldata,
    encode_uint256_word,
)


class TestThreatFeed(unittest.TestCase):
    """Test ThreatFeed data loading, updates, search, and invariant enforcement."""

    def setUp(self):
        self.feed = get_default_threat_feed()
        self.malicious_contract = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"  # Inferno Drainer
        self.phishing_eoa = "0x1234567890123456789012345678901234567890"  # Known phishing drainer
        self.dangerous_selector = "baa2abde"  # sweepTokens(address,address[])
        self.burn_selector = "42966c68"  # burnFrom(address,uint256)
        self.safe_target = DEFAULT_ALLOWED_TARGET

    def test_default_feed_contains_required_threat_types(self):
        """Threat feed must contain malicious contracts, phishing addresses, selectors, and attack patterns."""
        self.assertTrue(self.feed.is_address_blocked(self.malicious_contract))
        self.assertTrue(self.feed.is_address_blocked(self.phishing_eoa))
        self.assertTrue(self.feed.is_selector_blocked(self.dangerous_selector))
        self.assertTrue(self.feed.is_selector_blocked(TRANSFER_FROM_SELECTOR))

        # Check metadata retrieval
        threat_meta = self.feed.get_address_threat(self.malicious_contract)
        self.assertIsNotNone(threat_meta)
        self.assertIn("Inferno", threat_meta.name)
        self.assertEqual(threat_meta.severity, "CRITICAL")

        selector_meta = self.feed.get_selector_threat(self.dangerous_selector)
        self.assertIsNotNone(selector_meta)
        self.assertIn("sweepTokens", selector_meta.signature)

    def test_malicious_contract_blocked_in_strict_mode(self):
        """Known malicious contract must be blocked in strict mode with CRITICAL risk."""
        engine = PolicyEngine(PolicyConfig.strict())
        res = engine.evaluate_transaction_policy(self.malicious_contract, 0, "")
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res.reason)
        self.assertIn("threat feed", res.reason)

    def test_malicious_contract_blocked_in_balanced_mode(self):
        """Known malicious contract must be blocked in balanced mode."""
        engine = PolicyEngine(PolicyConfig.balanced())
        res = engine.evaluate_transaction_policy(self.malicious_contract, 0, "")
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res.reason)

    def test_malicious_contract_hard_blocked_in_degen_mode(self):
        """In degen mode, known malicious items must be hard-blocked even with confirmed=True."""
        # Degen mode with no restrictions, but threat feed is active
        cfg = PolicyConfig.degen(
            max_eth_per_tx=100 * 10**18,
            allow_unlimited_approve=True,
            contract_allowlist=[],  # empty allowlist allows general calls in degen
        )
        engine = PolicyEngine(cfg)

        # 1. Unconfirmed execution -> blocked
        res_unconfirmed = engine.evaluate_transaction_policy(self.malicious_contract, 0, "")
        self.assertFalse(res_unconfirmed.allowed)
        self.assertEqual(res_unconfirmed.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res_unconfirmed.reason)

        # 2. Confirmed execution (human confirmation granted) -> STILL hard-blocked!
        res_confirmed = engine.evaluate_transaction_policy(
            self.malicious_contract, 0, "", confirmed=True
        )
        self.assertFalse(res_confirmed.allowed)
        self.assertEqual(res_confirmed.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res_confirmed.reason)

    def test_phishing_address_blocked_when_recipient_or_target(self):
        """Phishing address must be blocked when called directly or as an ERC20 transfer recipient."""
        engine = PolicyEngine(PolicyConfig.degen())

        # Direct transfer to phishing address
        res_direct = engine.evaluate_transaction_policy(self.phishing_eoa, 10**17, "")
        self.assertFalse(res_direct.allowed)
        self.assertEqual(res_direct.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res_direct.reason)

        # ERC-20 transfer(address to, uint256 amount) where `to` is phishing address
        erc20_transfer_calldata = (
            "0xa9059cbb"
            + encode_address_word(self.phishing_eoa).hex()
            + encode_uint256_word(100).hex()
        )
        res_erc20 = engine.evaluate_transaction_policy(
            self.safe_target, 0, erc20_transfer_calldata
        )
        self.assertFalse(res_erc20.allowed)
        self.assertEqual(res_erc20.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res_erc20.reason)

    def test_phishing_address_blocked_as_approval_spender(self):
        """Phishing address must be blocked when an approve(spender, amount) targets it."""
        engine = PolicyEngine(PolicyConfig.degen())
        approve_calldata = (
            "0x095ea7b3"
            + encode_address_word(self.phishing_eoa).hex()
            + encode_uint256_word(1000).hex()
        )
        res = engine.evaluate_transaction_policy(self.safe_target, 0, approve_calldata)
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res.reason)

    def test_dangerous_selector_blocked_direct_and_multicall(self):
        """Dangerous function selector from blocklist must be blocked directly and inside multicall."""
        engine = PolicyEngine(PolicyConfig.degen())

        # Direct call with dangerous selector
        direct_calldata = "0x" + self.dangerous_selector + ("00" * 32)
        res_direct = engine.evaluate_transaction_policy(self.safe_target, 0, direct_calldata)
        self.assertFalse(res_direct.allowed)
        self.assertIn("selector blocked", res_direct.reason)

        # Smuggled inside multicall(bytes[])
        safe_call = bytes.fromhex("a9059cbb") + encode_address_word("0x01") + encode_uint256_word(10)
        dangerous_subcall = bytes.fromhex(self.dangerous_selector) + encode_address_word("0x01")
        smuggled_multicall = encode_multicall_calldata([safe_call, dangerous_subcall])

        res_smuggled = engine.evaluate_transaction_policy(self.safe_target, 0, smuggled_multicall)
        self.assertFalse(res_smuggled.allowed)
        self.assertIn("selector blocked", res_smuggled.reason)

    def test_cannot_approve_blocked_address_in_memory_store(self):
        """safeguard_approve_address must reject attempts to approve known bad addresses."""
        with self.assertRaises(ValueError) as ctx:
            safeguard_approve_address(
                self.malicious_contract,
                label="Attacker attempted override",
            )
        self.assertIn("blocked by threat feed", str(ctx.exception).lower())

    def test_pre_tool_call_blocks_threat_address(self):
        """check_pre_tool_call hook must intercept and block interaction with listed threat addresses."""
        res = check_pre_tool_call(
            tool_name="eth_sendTransaction",
            tool_args={
                "to": self.malicious_contract,
                "value": "0.1 ether",
                "data": "",
            },
            mode="degen",
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL)
        self.assertIn("denylisted", res.reason)

    def test_safeguard_search_threat_reports(self):
        """safeguard_search_threat_reports must return relevant reports by address, selector, keyword, or empty."""
        # 1. Search by address
        reports_addr = safeguard_search_threat_reports(self.malicious_contract)
        self.assertGreaterEqual(len(reports_addr), 1)
        self.assertIn("inferno", reports_addr[0]["name"].lower())

        # 2. Search by selector
        reports_sel = safeguard_search_threat_reports("sweepTokens")
        self.assertGreaterEqual(len(reports_sel), 1)
        self.assertIn("sweep", reports_sel[0]["signature"].lower())

        # 3. Search by attack pattern keyword
        reports_aap = safeguard_search_threat_reports("memory poisoning")
        self.assertGreaterEqual(len(reports_aap), 1)
        self.assertEqual(reports_aap[0]["id"], "AAP-001")
        self.assertIn("memory", reports_aap[0]["title"].lower())

        # 4. Search empty returns recent reports
        recent = safeguard_search_threat_reports(limit=5)
        self.assertEqual(len(recent), 5)

        # 5. search_threat_reports alias works identically
        reports_alias = search_threat_reports("inferno")
        self.assertGreaterEqual(len(reports_alias), 1)

    def test_custom_blocklist_file_loading_and_updates(self):
        """ThreatFeed must load custom JSON files and dynamically enforce additions."""
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            custom_data = {
                "version": "2.0.0",
                "updated_at": "2026-11-07T12:00:00Z",
                "malicious_contracts": [
                    {
                        "address": "0x5555555555555555555555555555555555559999",
                        "name": "Custom Bad Contract",
                        "description": "Dynamically added test drainer",
                        "severity": "CRITICAL",
                    }
                ],
                "dangerous_selectors": [
                    {
                        "selector": "12345678",
                        "signature": "customExploit(uint256)",
                        "description": "Custom exploit selector",
                    }
                ],
                "agent_attack_patterns": [
                    {
                        "id": "AAP-999",
                        "title": "Custom Agent Threat",
                        "description": "Test custom pattern",
                    }
                ],
            }
            json.dump(custom_data, tf)
            tf_path = tf.name

        try:
            feed = ThreatFeed(filepath=tf_path)
            self.assertTrue(feed.is_address_blocked("0x5555555555555555555555555555555555559999"))
            self.assertTrue(feed.is_selector_blocked("12345678"))

            cfg = PolicyConfig.degen(threat_feed=feed)
            engine = PolicyEngine(cfg)

            # Check address blocked
            res_addr = engine.evaluate_transaction_policy(
                "0x5555555555555555555555555555555555559999", 0, ""
            )
            self.assertFalse(res_addr.allowed)
            self.assertIn("denylisted", res_addr.reason)

            # Check selector blocked
            res_sel = engine.evaluate_transaction_policy(
                self.safe_target, 0, "0x1234567800000000"
            )
            self.assertFalse(res_sel.allowed)
            self.assertIn("selector blocked", res_sel.reason)

            # Dynamically add another address and verify it is blocked
            new_bad = "0x7777777777777777777777777777777777778888"
            feed.add_address(new_bad, name="Dynamically Added Phishing")
            self.assertTrue(feed.is_address_blocked(new_bad))

            res_dyn = engine.evaluate_transaction_policy(new_bad, 0, "")
            self.assertFalse(res_dyn.allowed)
            self.assertIn("denylisted", res_dyn.reason)

            # Save and confirm file updated
            feed.save()
            reloaded = ThreatFeed(filepath=tf_path)
            self.assertTrue(reloaded.is_address_blocked(new_bad))

        finally:
            if os.path.isfile(tf_path):
                os.remove(tf_path)

    def test_pre_tool_call_catches_nested_blocklist_hit(self):
        """Pre-tool-call inspection catches blocklisted addresses hidden inside nested tool_args structures."""
        # Nested dict with blocklisted phishing address
        nested_args = {
            "tx_data": {
                "recipient": self.phishing_eoa,
                "amount": "100000000000000000",
            }
        }
        res = check_pre_tool_call(
            tool_name="eth_sendTransaction",
            tool_args=nested_args,
            mode="degen",
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("denylisted", res.reason)

        # List of recipients with blocklisted address
        batch_args = {
            "recipients": [self.safe_target, self.malicious_contract],
            "values": [0, 0],
        }
        res_batch = check_pre_tool_call(
            tool_name="transfer",
            tool_args=batch_args,
            mode="balanced",
        )
        self.assertFalse(res_batch.allowed)
        self.assertEqual(res_batch.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("denylisted", res_batch.reason)

    def test_blocklist_hit_hard_blocks_in_verify_transaction_with_confirmation(self):
        """verify_transaction must hard-block any blocklist hit even if confirmed=True."""
        from verifier import verify_transaction
        for mode in ("strict", "balanced", "degen"):
            res = verify_transaction(
                to_address=self.malicious_contract,
                value_wei=0,
                data_hex="",
                config=PolicyConfig(mode=mode),
                confirmed=True,
            )
            self.assertFalse(res.allowed, f"Expected blocklist hit to be blocked in {mode} mode")
            self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
            self.assertIn("denylisted", res.reason)


if __name__ == "__main__":
    unittest.main()

