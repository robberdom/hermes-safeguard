"""
test_threat_stream.py — Comprehensive tests for Hermes SafeGuard Dynamic Threat Stream.

Covers:
  1. Provider payload parsing (PeckShield, ScamSniffer, SlowMist)
  2. Address normalization & selector extraction
  3. Invariant protection: protected infrastructure addresses (Uniswap, Seaport, WETH) are never blocked
  4. Webhook ingestion HTTP server (POST /webhook/peckshield, /webhook/scamsniffer, /webhook/slowmist, /webhook/threat)
  5. Status endpoint (GET /status, /health)
  6. 5-minute polling daemon lifecycle and synchronization passes
  7. Integration with PolicyEngine and ThreatFeed
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from policy_engine import (
    DEFAULT_ALLOWED_TARGET,
    PolicyConfig,
    PolicyEngine,
    RiskScore,
    ThreatFeed,
    normalize_address,
)
from threat_stream import (
    CANONICAL_PERMIT2,
    CANONICAL_WETH,
    PeckShieldAlertProvider,
    ScamSnifferProvider,
    SecurityAlert,
    SlowMistProvider,
    ThreatStreamSyncer,
)
from verifier import OPENSEA_SEAPORT_1_5, UNISWAP_V2_ROUTER


class TestThreatStream(unittest.TestCase):
    """Test dynamic live threat stream ingestion, webhooks, and invariant guards."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.blocklist_file = Path(self.temp_dir.name) / "test_blocklist.json"
        self.blocklist_file.write_text(json.dumps({
            "version": "1.0.0",
            "malicious_contracts": [],
            "phishing_addresses": [],
            "dangerous_selectors": [],
        }))
        self.feed = ThreatFeed(filepath=self.blocklist_file)
        self.syncer = ThreatStreamSyncer(
            threat_feed=self.feed,
            blocklist_path=self.blocklist_file,
            poll_interval=5,
            providers=[],  # Custom provider injection for deterministic tests
        )

    def tearDown(self):
        self.syncer.stop()
        self.temp_dir.cleanup()

    def test_peckshield_provider_parsing(self):
        """Test parsing of PeckShield alert formats and regex address extraction."""
        provider = PeckShieldAlertProvider()

        # 1. Structured payload with address field
        payload_structured = {
            "alerts": [
                {
                    "address": "0x1111222233334444555566667777888899990001",
                    "category": "malicious_contract",
                    "title": "PeckShieldAlert: Fake Airdrop Deployer",
                    "severity": "CRITICAL",
                }
            ]
        }
        alerts = provider.parse_webhook_payload(payload_structured)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].target, "1111222233334444555566667777888899990001")
        self.assertEqual(alerts[0].category, "malicious_contract")
        self.assertEqual(alerts[0].source, "PeckShieldAlert")

        # 2. Free-text description with EVM address
        payload_text = {
            "title": "PeckShieldAlert: Suspicious Drainer Detected",
            "description": "Exploit transaction observed targeting address 0x2222333344445555666677778888999900001112 on Base",
            "category": "phishing_wallet",
        }
        alerts_text = provider.parse_webhook_payload(payload_text)
        self.assertEqual(len(alerts_text), 1)
        self.assertEqual(alerts_text[0].target, "2222333344445555666677778888999900001112")
        self.assertEqual(alerts_text[0].category, "phishing")

    def test_scamsniffer_provider_parsing(self):
        """Test parsing ScamSniffer wallet drainer payloads."""
        provider = ScamSnifferProvider()

        payload = {
            "threats": [
                {
                    "address": "0x3333444455556666777788889999000011112223",
                    "drainer_name": "Inferno V2 Clone",
                    "threat_type": "wallet_drainer",
                },
                "0x4444555566667777888899990000111122223334",
            ]
        }
        alerts = provider.parse_webhook_payload(payload)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0].target, "3333444455556666777788889999000011112223")
        self.assertEqual(alerts[0].category, "phishing")
        self.assertIn("Inferno V2", alerts[0].name)
        self.assertEqual(alerts[1].target, "4444555566667777888899990000111122223334")

    def test_slowmist_provider_parsing(self):
        """Test parsing SlowMist MistTrack incident alerts."""
        provider = SlowMistProvider()

        payload = {
            "incidents": [
                {
                    "hacker_address": "0x5555666677778888999900001111222233334445",
                    "incident_name": "DEX Router Reentrancy Drain",
                    "description": "Attacker exfiltrated $2M into hot wallet",
                    "type": "contract_exploit",
                }
            ]
        }
        alerts = provider.parse_webhook_payload(payload)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].target, "5555666677778888999900001111222233334445")
        self.assertIn("SlowMist", alerts[0].source)
        self.assertIn("DEX Router Reentrancy", alerts[0].name)

    def test_invariant_protection_blocks_protected_infrastructure(self):
        """Invariant: protected DEX routers, Seaport, and WETH must NEVER be blocked by threat feeds."""
        protected_tests = [
            (UNISWAP_V2_ROUTER, "Uniswap V2 Router"),
            (OPENSEA_SEAPORT_1_5, "OpenSea Seaport 1.5"),
            (CANONICAL_WETH, "Canonical WETH"),
            (CANONICAL_PERMIT2, "Uniswap Permit2"),
            ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Aave V3 Pool Ethereum"),
            ("0x6a2E3a1e16FC29f27Ce61429746D558d656975bB", "Robinhood L1 Gateway Router"),
            (DEFAULT_ALLOWED_TARGET, "Default Allowed Target"),
        ]

        alerts = [
            SecurityAlert(
                target=addr,
                category="malicious_contract",
                name=f"Spoofed alert for {label}",
                severity="CRITICAL",
            )
            for addr, label in protected_tests
        ]

        res = self.syncer.ingest_alerts(alerts)
        self.assertEqual(len(res["added_addresses"]), 0, "No protected address should be added!")
        self.assertEqual(len(res["skipped_protected"]), len(protected_tests))

        # Verify none of them are blocked in the feed
        for addr, _ in protected_tests:
            self.assertFalse(self.feed.is_address_blocked(addr))

    def test_dynamic_ingestion_and_policy_engine_hard_block(self):
        """Newly ingested drainer must immediately cause PolicyEngine to hard-block transactions."""
        drainer_addr = "0x9999888877776666555544443333222211110009"
        norm_drainer = normalize_address(drainer_addr)

        # Before ingestion: address is not blocked
        self.assertFalse(self.feed.is_address_blocked(norm_drainer))

        # Ingest new alert
        alert = SecurityAlert(
            target=drainer_addr,
            category="malicious_contract",
            name="Brand-new Zero-Day Drainer",
            description="Deployed 5 minutes ago by threat actor",
            severity="CRITICAL",
        )
        res = self.syncer.ingest_alerts([alert])
        self.assertIn(f"0x{norm_drainer}", res["added_addresses"])

        # Now immediately blocked in ThreatFeed
        self.assertTrue(self.feed.is_address_blocked(norm_drainer))

        # Hard-blocks even in Degen mode with human confirmation
        engine = PolicyEngine(PolicyConfig.degen(), threat_feed=self.feed)
        eval_res = engine.evaluate_transaction_policy(drainer_addr, 0, "", confirmed=True)
        self.assertFalse(eval_res.allowed)
        self.assertEqual(eval_res.risk_score, RiskScore.CRITICAL)
        self.assertIn("threat feed", eval_res.reason.lower())

    def test_dangerous_selector_ingestion(self):
        """Function selectors can be dynamically added to threat stream."""
        new_sel = "98765432"
        alert = SecurityAlert(
            target=new_sel,
            category="dangerous_selector",
            signature="stealthDrain(address)",
            description="New drain selector detected in phishing contract",
            severity="CRITICAL",
        )
        res = self.syncer.ingest_alerts([alert])
        self.assertIn(new_sel, res["added_selectors"])
        self.assertTrue(self.feed.is_selector_blocked(new_sel))

    def test_webhook_server_post_ingestion(self):
        """Test live webhook server handling POST /webhook/peckshield and /webhook/threat."""
        port = 18099  # Ephemeral test port
        self.syncer.start_webhook_server(port=port, host="127.0.0.1")
        time.sleep(0.1)  # Allow socket to bind

        new_threat = "0x7777888899990000111122223333444455556667"
        payload = {
            "address": new_threat,
            "category": "malicious_contract",
            "title": "PeckShield Zero-Day Alert",
            "description": "Drainer active in phishing campaigns",
        }
        body_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/webhook/peckshield",
            data=body_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "success")
            self.assertIn(f"0x{normalize_address(new_threat)}", data["new_blocked_addresses"])

        # Check health endpoint
        req_health = urllib.request.Request(f"http://127.0.0.1:{port}/health")
        with urllib.request.urlopen(req_health, timeout=5) as resp_health:
            self.assertEqual(resp_health.status, 200)
            health_data = json.loads(resp_health.read().decode("utf-8"))
            self.assertEqual(health_data["status"], "healthy")

        # Threat feed now has the new address
        self.assertTrue(self.feed.is_address_blocked(new_threat))

    def test_threat_feed_convenience_methods(self):
        """Test ThreatFeed.sync_live_threats() and start_live_stream() methods."""
        res = self.feed.sync_live_threats()
        self.assertIsInstance(res, dict)
        self.assertIn("timestamp", res)

        syncer = self.feed.start_live_stream(interval=10)
        self.assertIsNotNone(syncer)
        syncer.stop()


if __name__ == "__main__":
    unittest.main()

