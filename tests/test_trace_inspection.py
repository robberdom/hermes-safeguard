"""
test_trace_inspection.py — Unit tests for transaction simulation, trace inspection,
and drain detection layer in Hermes SafeGuard.
"""

import threading
import time
import unittest
from http.server import HTTPServer

from policy_engine import (
    DEFAULT_ALLOWED_TARGET,
    PolicyConfig,
    RiskScore,
    VerificationResult,
)
from verifier import (
    OPENSEA_SEAPORT_1_5,
    UNISWAP_V2_ROUTER,
    _MockRPCHandler,
    encode_address_word,
    encode_nft_mint_calldata,
    encode_uint256_word,
    encode_v2_swap_calldata,
    inspect_execution_trace,
    is_rpc_available,
    ensure_test_rpc_server,
    verify_transaction,
    build_test_contract_bytecode,
    rpc_request,
    DEFAULT_RPC_URL,
    APPROVE_SELECTOR,
    EXPLOIT_DELEGATECALL_SELECTOR,
    DRAIN_APPROVAL_SELECTOR,
    MULTI_DRAIN_SELECTOR,
    UNEXPECTED_TRANSFER_SELECTOR,
    NEW_DEPLOY_SELECTOR,
    ROBINHOOD_L1_GATEWAY_ROUTER,
    encode_high_tax_swap_calldata,
    encode_extortion_tax_swap_calldata,
)


class TestTraceInspection(unittest.TestCase):
    """Test suite for simulation and trace inspection layer."""

    @classmethod
    def setUpClass(cls):
        ensure_test_rpc_server()

    def setUp(self):
        from policy_engine import reset_default_velocity_tracker
        reset_default_velocity_tracker()
        self.degen_contract = "0x000000000000000000000000000000000000C001"
        self.agent_wallet = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

    def test_legitimate_opensea_mint_passes_in_degen(self):
        """Legitimate OpenSea Seaport NFT mint should pass in degen mode with low/medium risk."""
        mint_val = 50_000_000_000_000_000  # 0.05 ETH
        mint_calldata = encode_nft_mint_calldata(1)
        res = verify_transaction(
            OPENSEA_SEAPORT_1_5,
            mint_val,
            mint_calldata,
            config=PolicyConfig.degen(),
        )
        self.assertTrue(res.allowed)
        self.assertIn(res.risk_score, (RiskScore.LOW.value, RiskScore.MEDIUM.value))

    def test_legitimate_general_nft_mint_passes_in_degen(self):
        """Legitimate general NFT mint on contract should pass in degen mode."""
        unverified_nft = "0x000000000000000000000000000000000000F001"
        mint_val = 50_000_000_000_000_000
        mint_calldata = encode_nft_mint_calldata(1)
        res = verify_transaction(
            unverified_nft,
            mint_val,
            mint_calldata,
            config=PolicyConfig.degen(),
        )
        self.assertTrue(res.allowed)
        self.assertIn(res.risk_score, (RiskScore.LOW.value, RiskScore.MEDIUM.value))

    def test_approval_plus_transferfrom_drain_fails_in_degen(self):
        """Approval + transferFrom drain in same transaction MUST fail even in degen mode."""
        spender_bad = encode_address_word("0x000000000000000000000000000000000000bad1").hex()
        drain_amount = encode_uint256_word(1000).hex()
        drain_calldata = "0x" + DRAIN_APPROVAL_SELECTOR + spender_bad + drain_amount

        res = verify_transaction(
            self.degen_contract,
            0,
            drain_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertTrue(
            "drain pattern" in res.reason or "approval + transferFrom" in res.reason,
            f"Expected drain pattern in reason, got: {res.reason}",
        )

    def test_normal_swap_with_reasonable_slippage_passes_in_balanced(self):
        """Normal swap with reasonable slippage should pass in balanced mode."""
        swap_router = UNISWAP_V2_ROUTER
        normal_swap_calldata = encode_v2_swap_calldata(
            amount_in=1_000_000_000_000_000_000,
            amount_out_min=950_000_000_000_000_000,  # 5% slippage
            path=[DEFAULT_ALLOWED_TARGET, "0x0000000000000000000000000000000000000002"],
            to=self.agent_wallet,
            deadline=1893456000,
        )
        res = verify_transaction(
            swap_router,
            0,
            normal_swap_calldata,
            config=PolicyConfig.balanced(recipient_allowlist=[swap_router]),
        )
        self.assertTrue(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.LOW.value)

    def test_normal_swap_with_reasonable_slippage_passes_in_degen(self):
        """Normal swap with reasonable slippage should pass in degen mode."""
        swap_router = UNISWAP_V2_ROUTER
        normal_swap_calldata = encode_v2_swap_calldata(
            amount_in=1_000_000_000_000_000_000,
            amount_out_min=950_000_000_000_000_000,
            path=[DEFAULT_ALLOWED_TARGET, "0x0000000000000000000000000000000000000002"],
            to=self.agent_wallet,
            deadline=1893456000,
        )
        res = verify_transaction(
            swap_router,
            0,
            normal_swap_calldata,
            config=PolicyConfig.degen(contract_allowlist=[swap_router]),
        )
        self.assertTrue(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.LOW.value)

    def test_unexpected_token_transfer_out_fails_in_degen(self):
        """Unexpected ERC-20 / NFT transfer out during trace must fail as critical risk."""
        unexpected_calldata = "0x" + UNEXPECTED_TRANSFER_SELECTOR + encode_uint256_word(1).hex()
        res = verify_transaction(
            self.degen_contract,
            50_000_000_000_000_000,
            unexpected_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("unexpected", res.reason.lower())

    def test_multiple_transfers_out_sweeper_drain_fails_in_degen(self):
        """Multiple transfers out of wallet in single tx must fail as critical drain."""
        multi_drain_calldata = "0x" + MULTI_DRAIN_SELECTOR + ("00" * 32)
        res = verify_transaction(
            self.degen_contract,
            0,
            multi_drain_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertTrue(
            "multiple transfers out" in res.reason or "drain pattern" in res.reason,
            f"Expected multiple transfers out alert, got: {res.reason}",
        )

    def test_unverified_delegatecall_fails_in_degen(self):
        """DELEGATECALL to unverified target must fail with critical risk even in degen mode."""
        exploit_calldata = "0x" + EXPLOIT_DELEGATECALL_SELECTOR + ("00" * 32)
        res = verify_transaction(
            self.degen_contract,
            0,
            exploit_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertTrue("Trace inspection" in res.reason or "balance loss" in res.reason)

    def test_newly_deployed_contract_blocked_in_strict_allowed_in_degen(self):
        """
        CALL to a newly deployed contract under the current mode model.

        * strict: refuses to run at all without an operator-deployed SafeGuardPolicy.sol
          (auto-deploy was removed) — CRITICAL. With a policy address configured, the
          trace inspector still flags the new-contract CALL and blocks it as HIGH risk.
        * degen is no longer an operator mode (stored "degen" resolves to balanced).
          The programmatic PolicyConfig.degen() preset with an explicit allowlist
          still lets this through with a MEDIUM-risk warning.
        """
        import storage

        new_deploy_calldata = "0x" + NEW_DEPLOY_SELECTOR + ("00" * 32)

        # strict without a deployed policy contract: fail closed, CRITICAL
        res_no_policy = verify_transaction(
            DEFAULT_ALLOWED_TARGET, 0, new_deploy_calldata, config=PolicyConfig.strict(),
        )
        self.assertFalse(res_no_policy.allowed)
        self.assertEqual(res_no_policy.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("no policy_address supplied", res_no_policy.reason)

        # strict with an operator-supplied policy address: trace inspection blocks as HIGH
        res_strict = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            new_deploy_calldata,
            policy_address="0x000000000000000000000000000000000000dEaD",
            config=PolicyConfig.strict(),
        )
        self.assertFalse(res_strict.allowed)
        self.assertEqual(res_strict.risk_score, RiskScore.HIGH.value)
        self.assertIn("newly deployed contract", res_strict.reason)

        # degen is retired as an operator mode
        self.assertEqual(storage.set_mode("degen"), "balanced")
        self.assertEqual(storage.get_mode(), "balanced")

        # explicit library preset still permits it with a warning
        res_degen = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            new_deploy_calldata,
            config=PolicyConfig.degen(contract_allowlist=[DEFAULT_ALLOWED_TARGET]),
        )
        self.assertTrue(res_degen.allowed)
        self.assertEqual(res_degen.risk_score, RiskScore.MEDIUM.value)
        self.assertIn("Warning", res_degen.reason)

    def test_normal_high_value_transfer_passes_in_degen(self):
        """A normal high-value transfer (e.g. 15 ETH) passes trace simulation in degen mode."""
        high_val = 15 * 10**18  # 15 ETH
        res = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            high_val,
            "",
            config=PolicyConfig.degen(),
        )
        self.assertTrue(res.allowed)
        self.assertFalse(res.requires_confirmation)

    def test_extortionate_token_tax_hard_blocked_in_degen(self):
        """Tokens with extortionate tax (e.g. 99% honeypot) MUST be hard-blocked even in degen mode."""
        extortion_calldata = encode_extortion_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
        res = verify_transaction(
            self.degen_contract,
            0,
            extortion_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("extortionate token tax", res.reason.lower())

    def test_extortionate_token_tax_hard_blocked_in_balanced(self):
        """Tokens with 99% honeypot tax must fail in balanced mode."""
        extortion_calldata = encode_extortion_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
        res = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            extortion_calldata,
            config=PolicyConfig.balanced(recipient_allowlist=[DEFAULT_ALLOWED_TARGET]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("extortionate token tax", res.reason.lower())

    def test_high_token_tax_warns_in_degen_mode(self):
        """Tokens with high tax between 25% and 50% (e.g. 30%) should return warning in degen mode."""
        high_tax_calldata = encode_high_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
        res = verify_transaction(
            self.degen_contract,
            0,
            high_tax_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertTrue(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.HIGH.value)
        self.assertIn("warning", res.warning.lower())
        self.assertIn("high token tax", res.warning.lower())

    def test_high_token_tax_blocks_in_strict_mode(self):
        """Tokens with high tax (30%) must be blocked in strict mode."""
        high_tax_calldata = encode_high_tax_swap_calldata("0x0000000000000000000000000000000000007001", 1_000_000)
        res = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            high_tax_calldata,
            config=PolicyConfig.strict(recipient_allowlist=[DEFAULT_ALLOWED_TARGET]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.HIGH.value)
        self.assertIn("high token tax", res.reason.lower())

    def test_robinhood_gateway_router_recognized(self):
        """Robinhood L1 Gateway router is recognized as a verified protocol and allowed in degen mode."""
        res = verify_transaction(
            ROBINHOOD_L1_GATEWAY_ROUTER,
            100_000_000_000_000_000,  # 0.1 ETH
            "",
            config=PolicyConfig.degen(),
        )
        self.assertTrue(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.LOW.value)

    def test_backward_compatible_unpacking(self):
        """VerificationResult should cleanly unpack as 2 items, 3 items, or object attributes."""
        res = VerificationResult(True, "all good", RiskScore.LOW)

        # Unpack 2 items (legacy style)
        allowed, reason = res
        self.assertTrue(allowed)
        self.assertEqual(reason, "all good")

        # Unpack 3 items (expanded style)
        allowed3, reason3, risk3 = res
        self.assertTrue(allowed3)
        self.assertEqual(reason3, "all good")
        self.assertEqual(risk3, "low")

        # Attribute access
        self.assertTrue(res.allowed)
        self.assertEqual(res.reason, "all good")
        self.assertEqual(res.risk_score, "low")

    def test_simulation_realistic_mint_to_allows_in_degen(self):
        """Realistic mintTo(caller, quantity) NFT mint passes simulation cleanly in degen mode."""
        mint_to_calldata = "0x755edd17" + encode_address_word(self.agent_wallet).hex() + encode_uint256_word(1).hex()
        res = verify_transaction(
            "0x000000000000000000000000000000000000F001",
            80_000_000_000_000_000,  # 0.08 ETH
            mint_to_calldata,
            config=PolicyConfig.degen(),
        )
        self.assertTrue(res.allowed)
        self.assertFalse(res.requires_confirmation)
        self.assertIn(res.risk_score, (RiskScore.LOW.value, RiskScore.MEDIUM.value))

    def test_simulation_catches_unexpected_token_outflow_during_nft_mint(self):
        """Simulation catches unexpected NFT/token transfer out during NFT mint and marks CRITICAL risk."""
        unexpected_calldata = "0x" + UNEXPECTED_TRANSFER_SELECTOR + encode_uint256_word(1).hex()
        res = verify_transaction(
            self.degen_contract,
            50_000_000_000_000_000,
            unexpected_calldata,
            config=PolicyConfig.degen(contract_allowlist=[self.degen_contract]),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.risk_score, RiskScore.CRITICAL.value)
        self.assertIn("unexpected erc-20/nft transfer out of wallet during nft mint", res.reason.lower())


if __name__ == "__main__":
    unittest.main()

