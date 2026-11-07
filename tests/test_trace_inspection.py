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
)


class TestTraceInspection(unittest.TestCase):
    """Test suite for simulation and trace inspection layer."""

    @classmethod
    def setUpClass(cls):
        cls.mock_server = None
        if not is_rpc_available("127.0.0.1", 8545):
            cls.mock_server = HTTPServer(("127.0.0.1", 8545), _MockRPCHandler)
            cls.server_thread = threading.Thread(target=cls.mock_server.serve_forever, daemon=True)
            cls.server_thread.start()
            time.sleep(0.1)
        else:
            mock_code = build_test_contract_bytecode(
                from_address="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                target_bad="0x000000000000000000000000000000000000bad1",
                tok1="0x0000000000000000000000000000000000007001",
                tok2="0x0000000000000000000000000000000000007002",
                nft1="0x000000000000000000000000000000000000ee01",
            )
            try:
                rpc_request(DEFAULT_RPC_URL, "anvil_setCode", [DEFAULT_ALLOWED_TARGET, mock_code])
                rpc_request(DEFAULT_RPC_URL, "anvil_setCode", ["0x000000000000000000000000000000000000C001", mock_code])
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        if cls.mock_server:
            cls.mock_server.shutdown()
            cls.mock_server.server_close()

    def setUp(self):
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
        """CALL to newly deployed contract is blocked in strict, allowed with warning in degen."""
        new_deploy_calldata = "0x" + NEW_DEPLOY_SELECTOR + ("00" * 32)

        # In strict mode: blocked as high risk
        res_strict = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            new_deploy_calldata,
            config=PolicyConfig.strict(),
        )
        self.assertFalse(res_strict.allowed)
        self.assertIn(res_strict.risk_score, (RiskScore.HIGH.value, RiskScore.MEDIUM.value))

        # In degen mode: allowed with warning as medium risk
        res_degen = verify_transaction(
            DEFAULT_ALLOWED_TARGET,
            0,
            new_deploy_calldata,
            config=PolicyConfig.degen(contract_allowlist=[DEFAULT_ALLOWED_TARGET]),
        )
        self.assertTrue(res_degen.allowed)
        self.assertEqual(res_degen.risk_score, RiskScore.MEDIUM.value)
        self.assertIn("Warning", res_degen.reason)

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


if __name__ == "__main__":
    unittest.main()

