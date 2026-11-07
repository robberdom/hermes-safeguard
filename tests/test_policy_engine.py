"""
test_policy_engine.py — Unit tests for PolicyConfig and PolicyEngine.
Uses standard library unittest.
"""

import unittest
from pathlib import Path

from policy_engine import (
    DEFAULT_ALLOWED_TARGET,
    APPROVE_SELECTOR,
    TRANSFER_FROM_SELECTOR,
    MULTICALL_SELECTOR,
    V2_SWAP_SELECTOR,
    V3_SWAP_SELECTOR,
    SET_APPROVAL_FOR_ALL_SELECTOR,
    PERMIT2_APPROVE_SELECTOR,
    UINT256_MAX,
    PolicyConfig,
    PolicyEngine,
    PolicyMode,
    decode_bytes_array,
    normalize_address,
)
from verifier import (
    encode_address_word,
    encode_uint256_word,
    encode_multicall_calldata,
    encode_v2_swap_calldata,
    verify_transaction,
)


class TestPolicyConfig(unittest.TestCase):
    """Test PolicyConfig creation, validation, invariants, and serialization."""

    def test_strict_defaults(self):
        cfg = PolicyConfig.strict()
        self.assertEqual(cfg.mode, "strict")
        self.assertEqual(cfg.max_eth_per_tx, 500_000_000_000_000_000)
        self.assertFalse(cfg.allow_unlimited_approve)
        self.assertTrue(cfg.require_simulation)
        self.assertTrue(cfg.block_zero_slippage)
        self.assertEqual(len(cfg.recipient_allowlist), 1)

    def test_balanced_defaults(self):
        cfg = PolicyConfig.balanced()
        self.assertEqual(cfg.mode, "balanced")
        self.assertEqual(cfg.max_eth_per_tx, 5_000_000_000_000_000_000)
        self.assertFalse(cfg.allow_unlimited_approve)
        self.assertTrue(cfg.require_simulation)
        self.assertTrue(cfg.block_zero_slippage)

    def test_degen_defaults(self):
        cfg = PolicyConfig.degen()
        self.assertEqual(cfg.mode, "degen")
        self.assertEqual(cfg.max_eth_per_tx, 100_000_000_000_000_000_000)
        self.assertEqual(cfg.max_token_per_tx, UINT256_MAX)
        self.assertTrue(cfg.allow_unlimited_approve)
        self.assertTrue(cfg.require_simulation)
        self.assertFalse(cfg.block_zero_slippage)

    def test_invariants_enforced(self):
        # require_simulation is always forced to True
        cfg = PolicyConfig.from_dict({
            "mode": "degen",
            "require_simulation": False,
        })
        self.assertTrue(cfg.require_simulation)

        # allow_unlimited_approve cannot be True in strict or balanced mode
        cfg_strict = PolicyConfig.from_dict({
            "mode": "strict",
            "allow_unlimited_approve": True,
        })
        self.assertFalse(cfg_strict.allow_unlimited_approve)

        cfg_balanced = PolicyConfig.from_dict({
            "mode": "balanced",
            "allow_unlimited_approve": True,
        })
        self.assertFalse(cfg_balanced.allow_unlimited_approve)

        # block_zero_slippage cannot be False in strict or balanced mode
        cfg_strict_slip = PolicyConfig.from_dict({
            "mode": "strict",
            "block_zero_slippage": False,
        })
        self.assertTrue(cfg_strict_slip.block_zero_slippage)

    def test_yaml_roundtrip(self):
        cfg = PolicyConfig.degen(
            contract_allowlist=["0x000000000000000000000000000000000000C001"],
            recipient_denylist=["0x000000000000000000000000000000000000BAD1"],
        )
        yaml_str = cfg.to_yaml()
        loaded = PolicyConfig.from_yaml(yaml_str)
        self.assertEqual(loaded.mode, "degen")
        self.assertEqual(loaded.max_eth_per_tx, cfg.max_eth_per_tx)
        self.assertTrue(loaded.allow_unlimited_approve)
        self.assertEqual(len(loaded.contract_allowlist), 1)
        self.assertEqual(len(loaded.recipient_denylist), 1)


class TestPolicyEngine(unittest.TestCase):
    """Test policy evaluation rules across strict, balanced, and degen modes."""

    def setUp(self):
        self.target = DEFAULT_ALLOWED_TARGET
        self.degen_contract = "0x000000000000000000000000000000000000C001"
        self.bad_target = "0x000000000000000000000000000000000000BAD1"

        spender = encode_address_word("0x0000000000000000000000000000000000000001").hex()
        unlimited_amount = "f" * 64
        self.approve_unlimited = "0x" + APPROVE_SELECTOR + spender + unlimited_amount

        safe_call = bytes.fromhex("a9059cbb") + encode_address_word("0x01") + encode_uint256_word(100)
        drain_call = bytes.fromhex(TRANSFER_FROM_SELECTOR) + encode_address_word("0x01") + encode_address_word("0x02") + encode_uint256_word(100)
        self.multicall_drain = encode_multicall_calldata([safe_call, drain_call])

    def test_strict_mode(self):
        engine = PolicyEngine(PolicyConfig.strict())

        # Safe transfer
        allowed, _ = engine.evaluate_transaction_policy(self.target, 10**17, "")
        self.assertTrue(allowed)

        # High value (> 0.5 ETH)
        allowed, reason = engine.evaluate_transaction_policy(self.target, 10**18, "")
        self.assertFalse(allowed)
        self.assertIn("value exceeds max per tx", reason)

        # Unlimited approve blocked
        allowed, reason = engine.evaluate_transaction_policy(self.target, 0, self.approve_unlimited)
        self.assertFalse(allowed)
        self.assertIn("unbounded approve blocked", reason)

        # Smuggled drain blocked
        allowed, reason = engine.evaluate_transaction_policy(self.target, 0, self.multicall_drain)
        self.assertFalse(allowed)
        self.assertIn("selector blocked", reason)

    def test_balanced_mode(self):
        engine = PolicyEngine(PolicyConfig.balanced(recipient_allowlist=[self.target]))

        # Higher value (1.0 ETH allowed within 5.0 ETH cap)
        allowed, _ = engine.evaluate_transaction_policy(self.target, 10**18, "")
        self.assertTrue(allowed)

        # Exceeds balanced value cap (> 5.0 ETH)
        allowed, reason = engine.evaluate_transaction_policy(self.target, 6 * 10**18, "")
        self.assertFalse(allowed)
        self.assertIn("value exceeds max per tx", reason)

        # Unlimited approve STILL blocked
        allowed, reason = engine.evaluate_transaction_policy(self.target, 0, self.approve_unlimited)
        self.assertFalse(allowed)
        self.assertIn("unbounded approve blocked", reason)

        # Smuggled drain STILL blocked
        allowed, reason = engine.evaluate_transaction_policy(self.target, 0, self.multicall_drain)
        self.assertFalse(allowed)
        self.assertIn("selector blocked", reason)

    def test_degen_mode(self):
        cfg = PolicyConfig.degen(
            contract_allowlist=[self.degen_contract],
            recipient_denylist=[self.bad_target],
        )
        engine = PolicyEngine(cfg)

        # High value (5.0 ETH) allowed in degen mode
        allowed, _ = engine.evaluate_transaction_policy(self.degen_contract, 5 * 10**18, "")
        self.assertTrue(allowed)

        # Unlimited approve allowed in degen mode on whitelisted contract
        allowed, _ = engine.evaluate_transaction_policy(self.degen_contract, 0, self.approve_unlimited)
        self.assertTrue(allowed)

        # Clear drain (smuggled multicall drain) STILL blocked in degen mode
        allowed, reason = engine.evaluate_transaction_policy(self.degen_contract, 0, self.multicall_drain)
        self.assertFalse(allowed)
        self.assertIn("selector blocked", reason)

        # Denylisted target blocked in degen mode
        allowed, reason = engine.evaluate_transaction_policy(self.bad_target, 0, "")
        self.assertFalse(allowed)
        self.assertIn("denylisted", reason)

        # Unverified contract blocked when contract_allowlist is set
        unverified = "0x000000000000000000000000000000000000DEAD"
        allowed, reason = engine.evaluate_transaction_policy(unverified, 0, self.approve_unlimited)
        self.assertFalse(allowed)
        self.assertIn("contract allowlist", reason)


if __name__ == "__main__":
    unittest.main()

