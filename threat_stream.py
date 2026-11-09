#!/usr/bin/env python3
"""
threat_stream.py — Dynamic Web3 Threat Intelligence Ingestion & Live Stream Service.

Provides real-time threat feed ingestion for Hermes SafeGuard by:
1. Regularly polling Web3 security alert APIs (PeckShield, ScamSniffer, SlowMist)
   on a 5-minute schedule (configurable via --interval or SAFEGUARD_THREAT_POLL_INTERVAL).
2. Hosting a lightweight webhook ingestion server (POST /webhook/peckshield,
   /webhook/scamsniffer, /webhook/slowmist, /webhook/threat) to immediately capture
   live zero-day drainer contract alerts and phishing sweeps.
3. Validating EVM addresses, enforcing non-blockable protected protocol invariants
   (Uniswap, Seaport, WETH, Permit2), and atomically writing updates to blocklist.json.
4. Dynamically updating in-memory ThreatFeed instances across active SafeGuard agents.

Standard library only (zero external pip dependencies).
"""

from __future__ import annotations

import argparse
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

# Import SafeGuard threat feed primitives
try:
    from policy_engine import (
        DEFAULT_ALLOWED_TARGET,
        ThreatEntry,
        ThreatFeed,
        get_default_threat_feed,
        normalize_address,
    )
    from verifier import KNOWN_VERIFIED_PROTOCOLS
except ImportError:
    # Standalone fallback if invoked without policy_engine in sys.path
    sys.path.insert(0, str(Path(__file__).parent))
    from policy_engine import (
        DEFAULT_ALLOWED_TARGET,
        ThreatEntry,
        ThreatFeed,
        get_default_threat_feed,
        normalize_address,
    )
    from verifier import KNOWN_VERIFIED_PROTOCOLS

logger = logging.getLogger("safeguard.threat_stream")

# ==============================================================================
# Invariant Protection: Immutable Core Infrastructure Allowlists
# ==============================================================================
# Security feeds must NEVER be allowed to poison core DEX, bridge, or native contracts.
CANONICAL_WETH = normalize_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
CANONICAL_WBTC = normalize_address("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599")
CANONICAL_USDC_ETH = normalize_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
CANONICAL_USDC_BASE = normalize_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
CANONICAL_USDT = normalize_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
CANONICAL_DAI = normalize_address("0x6B175474E89094C44Da98b954EedeAC495271d0F")
CANONICAL_PERMIT2 = normalize_address("0x000000000022D473030F116dDEE9F6B43aC78BA3")
ZERO_ADDRESS = normalize_address("0x0000000000000000000000000000000000000000")

PROTECTED_INFRASTRUCTURE_ADDRESSES: set[str] = {
    *KNOWN_VERIFIED_PROTOCOLS,
    CANONICAL_WETH,
    CANONICAL_WBTC,
    CANONICAL_USDC_ETH,
    CANONICAL_USDC_BASE,
    CANONICAL_USDT,
    CANONICAL_DAI,
    CANONICAL_PERMIT2,
    ZERO_ADDRESS,
    normalize_address(DEFAULT_ALLOWED_TARGET),
}

# 60s (1-minute) polling for rapid detection of fresh zero-day drainers,
# with live webhooks providing sub-second instantaneous alert delivery.
DEFAULT_POLL_INTERVAL_SECONDS = 60
DEFAULT_WEBHOOK_PORT = 8088


# ==============================================================================
# Security Alert Data Structure
# ==============================================================================

@dataclass
class SecurityAlert:
    target: str  # 40-character hex EVM address or 8-char function selector
    category: str  # "malicious_contract", "phishing", "dangerous_selector"
    name: str = ""
    signature: str = ""
    description: str = ""
    severity: str = "CRITICAL"
    source: str = "web3_security_stream"
    indicators: list[str] = field(default_factory=list)
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ==============================================================================
# Web3 Security Threat Providers
# ==============================================================================

class BaseThreatProvider:
    """Abstract base provider for Web3 threat intelligence streams."""

    name: str = "base_provider"

    def fetch_latest_threats(self) -> list[SecurityAlert]:
        """Poll the provider's API for recent threat reports and drainer addresses."""
        raise NotImplementedError

    def parse_webhook_payload(self, payload: dict[str, Any]) -> list[SecurityAlert]:
        """Parse incoming webhook event body into a list of SecurityAlerts."""
        raise NotImplementedError


class PeckShieldAlertProvider(BaseThreatProvider):
    """
    Ingests live exploit and drainer reports from PeckShield Alerts.
    Monitors on-chain exploiters, compromised deployers, and phishing addresses.
    """

    name: str = "PeckShield"

    def __init__(self, api_url: str | None = None, api_key: str | None = None) -> None:
        self.api_url = (
            api_url
            or os.getenv("PECKSHIELD_API_URL", "").strip()
            or os.getenv("PECKSHIELD_FEED_URL", "").strip()
        )
        self.api_key = api_key or os.getenv("PECKSHIELD_API_KEY", "").strip()

    def fetch_latest_threats(self) -> list[SecurityAlert]:
        if not self.api_url:
            return []

        try:
            headers = {"User-Agent": "Hermes-SafeGuard/1.0 (PeckShield-Threat-Ingestion)"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            req = urllib.request.Request(self.api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return self._parse_items(data)
        except Exception as e:
            logger.debug("PeckShield API poll failed (%s): %s", self.api_url, e)
            return []

    def parse_webhook_payload(self, payload: dict[str, Any]) -> list[SecurityAlert]:
        return self._parse_items(payload)

    def _parse_items(self, data: Any) -> list[SecurityAlert]:
        alerts: list[SecurityAlert] = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        items: list[dict[str, Any]] = []
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            if "alerts" in data and isinstance(data["alerts"], list):
                items = [x for x in data["alerts"] if isinstance(x, dict)]
            elif "data" in data and isinstance(data["data"], list):
                items = [x for x in data["data"] if isinstance(x, dict)]
            else:
                items = [data]

        for item in items:
            raw_addr = (
                item.get("address")
                or item.get("attacker")
                or item.get("contract_address")
                or item.get("target")
                or ""
            )
            if not raw_addr:
                # Check for address in text description via regex
                desc = item.get("description", "") or item.get("title", "") or ""
                m = re.search(r"0x[a-fA-F0-9]{40}", desc)
                if m:
                    raw_addr = m.group(0)

            if not raw_addr:
                continue

            try:
                norm = normalize_address(str(raw_addr))
            except Exception:
                continue

            cat = str(item.get("category", "malicious_contract")).lower()
            if "phish" in cat or "eoa" in cat or "drainer_wallet" in cat:
                cat = "phishing"
            else:
                cat = "malicious_contract"

            label = (
                item.get("label")
                or item.get("tag")
                or item.get("drainer_name")
                or item.get("scammer")
                or item.get("actor")
                or item.get("name")
                or item.get("title")
                or f"PeckShield Alert: 0x{norm[:6]}...{norm[-4:]}"
            )
            description = (
                item.get("description")
                or item.get("reason")
                or item.get("details")
                or f"Flagged by PeckShield Alert as active threat target 0x{norm}"
            )
            severity = str(item.get("severity", "CRITICAL")).upper()

            alerts.append(SecurityAlert(
                target=norm,
                category=cat,
                name=str(label),
                description=str(description),
                severity=severity,
                source="PeckShieldAlert",
                indicators=list(item.get("indicators", ["peckshield_alert", "exploit_target"])),
                timestamp=str(item.get("timestamp", now_iso)),
                metadata={"original_payload": item},
            ))

        return alerts


class ScamSnifferProvider(BaseThreatProvider):
    """
    Ingests live wallet drainer contracts and phishing domains from ScamSniffer.
    Specializes in Angel Drainer, Inferno, MS Drainer, and Permit2 phishing proxies.
    """

    name: str = "ScamSniffer"

    def __init__(self, api_url: str | None = None, api_key: str | None = None) -> None:
        self.api_url = (
            api_url
            or os.getenv("SCAMSNIFFER_API_URL", "").strip()
            or os.getenv("SCAMSNIFFER_FEED_URL", "").strip()
        )
        self.api_key = api_key or os.getenv("SCAMSNIFFER_API_KEY", "").strip()

    def fetch_latest_threats(self) -> list[SecurityAlert]:
        if not self.api_url:
            return []

        try:
            headers = {"User-Agent": "Hermes-SafeGuard/1.0 (ScamSniffer-Threat-Ingestion)"}
            if self.api_key:
                headers["x-api-key"] = self.api_key
            req = urllib.request.Request(self.api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return self._parse_items(data)
        except Exception as e:
            logger.debug("ScamSniffer API poll failed (%s): %s", self.api_url, e)
            return []

    def parse_webhook_payload(self, payload: dict[str, Any]) -> list[SecurityAlert]:
        return self._parse_items(payload)

    def _parse_items(self, data: Any) -> list[SecurityAlert]:
        alerts: list[SecurityAlert] = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        items: list[dict[str, Any]] = []
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    items.append(entry)
                elif isinstance(entry, str):
                    items.append({"address": entry, "category": "phishing"})
        elif isinstance(data, dict):
            # Might be structured as {"addresses": [...]} or {"blacklist": [...]}
            for key in ("addresses", "blacklist", "records", "data", "threats"):
                if key in data and isinstance(data[key], list):
                    for sub in data[key]:
                        if isinstance(sub, dict):
                            items.append(sub)
                        elif isinstance(sub, str):
                            items.append({"address": sub, "category": "phishing"})
            if not items:
                items = [data]

        for item in items:
            raw_addr = item.get("address") or item.get("contract") or item.get("wallet") or ""
            if not raw_addr:
                continue

            try:
                norm = normalize_address(str(raw_addr))
            except Exception:
                continue

            threat_type = str(item.get("threat_type", item.get("category", "malicious_contract"))).lower()
            category = "phishing" if ("phish" in threat_type or "drain" in threat_type) else "malicious_contract"
            label = (
                item.get("label")
                or item.get("tag")
                or item.get("drainer_name")
                or item.get("scammer")
                or item.get("actor")
                or item.get("name")
                or item.get("title")
                or f"ScamSniffer Drainer: 0x{norm[:6]}...{norm[-4:]}"
            )
            desc = (
                item.get("description")
                or item.get("reason")
                or item.get("details")
                or f"Identified by ScamSniffer as {threat_type} ({label})"
            )

            alerts.append(SecurityAlert(
                target=norm,
                category=category,
                name=str(label),
                description=str(desc),
                severity="CRITICAL",
                source="ScamSniffer",
                indicators=list(item.get("indicators", ["scamsniffer", "drainer_detection"])),
                timestamp=str(item.get("timestamp", now_iso)),
                metadata={"original_payload": item},
            ))

        return alerts


class SlowMistProvider(BaseThreatProvider):
    """
    Ingests live hack and incident threat alerts from SlowMist MistTrack / Web3Bugs.
    Specializes in stolen fund sweepers, malicious honeypot tokens, and bridge exploits.
    """

    name: str = "SlowMist"

    def __init__(self, api_url: str | None = None, api_key: str | None = None) -> None:
        self.api_url = (
            api_url
            or os.getenv("SLOWMIST_API_URL", "").strip()
            or os.getenv("MISTTRACK_API_URL", "").strip()
        )
        self.api_key = api_key or os.getenv("SLOWMIST_API_KEY", "").strip()

    def fetch_latest_threats(self) -> list[SecurityAlert]:
        if not self.api_url:
            return []

        try:
            headers = {"User-Agent": "Hermes-SafeGuard/1.0 (SlowMist-Threat-Ingestion)"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            req = urllib.request.Request(self.api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return self._parse_items(data)
        except Exception as e:
            logger.debug("SlowMist API poll failed (%s): %s", self.api_url, e)
            return []

    def parse_webhook_payload(self, payload: dict[str, Any]) -> list[SecurityAlert]:
        return self._parse_items(payload)

    def _parse_items(self, data: Any) -> list[SecurityAlert]:
        alerts: list[SecurityAlert] = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        items: list[dict[str, Any]] = []
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            for k in ("data", "incidents", "addresses", "hacks"):
                if k in data and isinstance(data[k], list):
                    items = [x for x in data[k] if isinstance(x, dict)]
                    break
            if not items:
                items = [data]

        for item in items:
            raw_addr = (
                item.get("address")
                or item.get("hacker_address")
                or item.get("stolen_funds_address")
                or item.get("target")
                or ""
            )
            if not raw_addr:
                continue

            try:
                norm = normalize_address(str(raw_addr))
            except Exception:
                continue

            label = (
                item.get("label")
                or item.get("tag")
                or item.get("incident_name")
                or item.get("drainer_name")
                or item.get("scammer")
                or item.get("actor")
                or item.get("title")
                or item.get("name")
                or "SlowMist Security Incident"
            )
            desc = (
                item.get("description")
                or item.get("reason")
                or item.get("details")
                or f"SlowMist MistTrack flagged address 0x{norm} involved in incident: {label}"
            )

            alerts.append(SecurityAlert(
                target=norm,
                category="phishing" if "wallet" in str(item.get("type", "")).lower() else "malicious_contract",
                name=f"SlowMist: {label}",
                description=str(desc),
                severity="CRITICAL",
                source="SlowMist",
                indicators=list(item.get("indicators", ["slowmist_alert", "misttrack"])),
                timestamp=str(item.get("timestamp", now_iso)),
                metadata={"incident": item},
            ))

        return alerts


# ==============================================================================
# Dynamic Threat Stream Syncer & Daemon Manager
# ==============================================================================

class ThreatStreamSyncer:
    """
    Coordinates continuous polling of Web3 security feeds and webhook ingestion.
    Synchronizes newly discovered drainers with ThreatFeed and disk blocklist.json.
    """

    def __init__(
        self,
        threat_feed: ThreatFeed | None = None,
        blocklist_path: str | Path | None = None,
        poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
        providers: list[BaseThreatProvider] | None = None,
        auto_save: bool = True,
    ) -> None:
        self.threat_feed: ThreatFeed = threat_feed or get_default_threat_feed()
        self.blocklist_path: Path | None = (
            Path(blocklist_path)
            if blocklist_path
            else (self.threat_feed.filepath or Path("blocklist.json"))
        )
        self.poll_interval: int = max(5, int(poll_interval))
        self.auto_save = auto_save

        # Registered Providers
        if providers is not None:
            self.providers = list(providers)
        else:
            self.providers = [
                PeckShieldAlertProvider(),
                ScamSnifferProvider(),
                SlowMistProvider(),
            ]

        self._lock = threading.Lock()
        self._running = False
        self._poll_thread: threading.Thread | None = None
        self._webhook_server: http.server.HTTPServer | None = None
        self._webhook_thread: threading.Thread | None = None

        # Telemetry & Status
        self.last_poll_time: float = 0.0
        self.total_polls: int = 0
        self.total_ingested_addresses: int = 0
        self.total_ingested_selectors: int = 0
        self.last_sync_result: dict[str, Any] = {}

    def register_provider(self, provider: BaseThreatProvider) -> None:
        """Register a new intelligence feed provider."""
        with self._lock:
            self.providers.append(provider)

    def ingest_alerts(self, alerts: list[SecurityAlert]) -> dict[str, Any]:
        """
        Validate, normalize, and commit a list of SecurityAlerts to ThreatFeed.
        Ensures invariant protection (never blocks canonical routers or WETH).
        """
        added_addrs: list[str] = []
        added_selectors: list[str] = []
        skipped_protected: list[str] = []
        already_blocked: list[str] = []

        with self._lock:
            for alert in alerts:
                target = alert.target.strip()
                if not target:
                    continue

                # Selector check (8 hex characters)
                if len(target) == 8 and all(c in "0123456789abcdefABCDEF" for c in target):
                    raw_sel = target.lower()
                    if self.threat_feed.is_selector_blocked(raw_sel):
                        already_blocked.append(raw_sel)
                    else:
                        self.threat_feed.add_selector(
                            raw_sel,
                            signature=alert.signature or f"selector_0x{raw_sel}",
                            description=alert.description or f"Dynamic ingest: {alert.name}",
                            severity=alert.severity,
                        )
                        added_selectors.append(raw_sel)
                    continue

                # EVM Address check (40 hex characters)
                try:
                    norm = normalize_address(target)
                except Exception:
                    continue

                # Invariant Protection: Refuse to block canonical core infrastructure
                if norm in PROTECTED_INFRASTRUCTURE_ADDRESSES:
                    skipped_protected.append(f"0x{norm}")
                    logger.warning(
                        "Security Feed Invariant Guard: Prevented ingestion of protected address 0x%s (%s)",
                        norm, alert.name
                    )
                    continue

                # Check if already blocked in current threat feed
                if self.threat_feed.is_address_blocked(norm):
                    already_blocked.append(f"0x{norm}")
                    continue

                # Ingest new address threat
                self.threat_feed.add_address(
                    address=f"0x{norm}",
                    category=alert.category,
                    name=alert.name or f"Live Ingest: 0x{norm[:6]}...{norm[-4:]}",
                    description=alert.description or f"Dynamically ingested from {alert.source}",
                    severity=alert.severity,
                    date_added=time.strftime("%Y-%m-%d"),
                )
                added_addrs.append(f"0x{norm}")

                # If report details present, add incident report
                report = {
                    "id": f"LIVE-{norm[:8].upper()}",
                    "type": alert.category,
                    "target": f"0x{norm}",
                    "name": alert.name,
                    "title": alert.name,
                    "category": alert.category,
                    "severity": alert.severity,
                    "description": alert.description,
                    "date_reported": alert.timestamp or time.strftime("%Y-%m-%d"),
                    "source": alert.source,
                    "indicators": alert.indicators or ["dynamic_stream_ingestion"],
                    "metadata": alert.metadata,
                }
                self.threat_feed.add_report(report)

            self.total_ingested_addresses += len(added_addrs)
            self.total_ingested_selectors += len(added_selectors)

            # Auto-save changes to persistent blocklist.json file if new threats added
            if (added_addrs or added_selectors) and self.auto_save and self.blocklist_path:
                try:
                    self.threat_feed.save(self.blocklist_path)
                except Exception as e:
                    logger.error("Failed to save threat feed to %s: %s", self.blocklist_path, e)

        return {
            "added_addresses": added_addrs,
            "added_selectors": added_selectors,
            "skipped_protected": skipped_protected,
            "already_blocked": already_blocked,
            "total_threat_addresses": len(self.threat_feed.blocked_addresses),
            "total_threat_selectors": len(self.threat_feed.blocked_selectors),
        }

    def sync_once(self) -> dict[str, Any]:
        """Run a single synchronization pass across all configured providers."""
        start_time = time.time()
        collected_alerts: list[SecurityAlert] = []
        provider_stats: dict[str, int] = {}

        for provider in self.providers:
            try:
                alerts = provider.fetch_latest_threats()
                provider_stats[provider.name] = len(alerts)
                collected_alerts.extend(alerts)
            except Exception as e:
                provider_stats[provider.name] = -1
                logger.error("Provider %s failed during fetch: %s", provider.name, e)

        ingest_res = self.ingest_alerts(collected_alerts)

        duration = time.time() - start_time
        self.last_poll_time = time.time()
        self.total_polls += 1

        res = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round(duration, 3),
            "providers_polled": provider_stats,
            "new_addresses": ingest_res["added_addresses"],
            "new_selectors": ingest_res["added_selectors"],
            "total_active_threat_addresses": ingest_res["total_threat_addresses"],
            "total_active_threat_selectors": ingest_res["total_threat_selectors"],
        }
        self.last_sync_result = res
        return res

    def start_polling_worker(self) -> None:
        """Launch background worker polling every `poll_interval` seconds."""
        with self._lock:
            if self._running:
                return
            self._running = True

        def _worker_loop():
            logger.info(
                "Threat stream polling daemon started (interval: %ds, providers: %d)",
                self.poll_interval, len(self.providers)
            )
            while self._running:
                try:
                    self.sync_once()
                except Exception as e:
                    logger.error("Error during scheduled threat feed poll: %s", e)

                # Sleep in short increments for responsive stopping
                slept = 0
                while self._running and slept < self.poll_interval:
                    time.sleep(1)
                    slept += 1

            logger.info("Threat stream polling daemon stopped.")

        t = threading.Thread(target=_worker_loop, name="ThreatStream-Poller", daemon=True)
        self._poll_thread = t
        t.start()

    def start_webhook_server(self, port: int = DEFAULT_WEBHOOK_PORT, host: str = "0.0.0.0") -> None:
        """Start dynamic webhook server receiving live Web3 alerts."""
        if self._webhook_server is not None:
            return

        syncer_ref = self

        class _WebhookHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                # Route through standard logging
                logger.debug("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)

            def do_GET(self) -> None:
                if self.path in ("/health", "/status"):
                    body = json.dumps({
                        "status": "healthy",
                        "uptime_seconds": round(time.time() - syncer_ref.last_poll_time, 1) if syncer_ref.last_poll_time else 0,
                        "total_polls": syncer_ref.total_polls,
                        "total_ingested_addresses": syncer_ref.total_ingested_addresses,
                        "active_threat_addresses": len(syncer_ref.threat_feed.blocked_addresses),
                        "active_threat_selectors": len(syncer_ref.threat_feed.blocked_selectors),
                        "providers": [p.name for p in syncer_ref.providers],
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404, "Not Found")

            def do_POST(self) -> None:
                # Parse route: /webhook/<provider> or /webhook/threat
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path.rstrip("/")

                length = int(self.headers.get("Content-Length", 0))
                if length <= 0 or length > 5_000_000:
                    self.send_error(400, "Invalid payload size")
                    return

                try:
                    raw_body = self.rfile.read(length).decode("utf-8")
                    payload = json.loads(raw_body)
                except Exception as e:
                    self.send_error(400, f"Malformed JSON: {e}")
                    return

                alerts: list[SecurityAlert] = []

                if path == "/webhook/peckshield":
                    provider = PeckShieldAlertProvider()
                    alerts = provider.parse_webhook_payload(payload)
                elif path == "/webhook/scamsniffer":
                    provider = ScamSnifferProvider()
                    alerts = provider.parse_webhook_payload(payload)
                elif path == "/webhook/slowmist":
                    provider = SlowMistProvider()
                    alerts = provider.parse_webhook_payload(payload)
                elif path in ("/webhook", "/webhook/threat"):
                    # Auto-detect or route through all providers
                    for p in syncer_ref.providers:
                        res = p.parse_webhook_payload(payload)
                        if res:
                            alerts.extend(res)
                            break
                    if not alerts:
                        # Fallback generic parsing
                        provider = PeckShieldAlertProvider()
                        alerts = provider.parse_webhook_payload(payload)
                else:
                    self.send_error(404, f"Unknown webhook endpoint: {path}")
                    return

                ingest_res = syncer_ref.ingest_alerts(alerts)
                resp_data = {
                    "status": "success",
                    "received_alerts": len(alerts),
                    "new_blocked_addresses": ingest_res["added_addresses"],
                    "new_blocked_selectors": ingest_res["added_selectors"],
                    "total_active_threat_addresses": ingest_res["total_threat_addresses"],
                }
                body = json.dumps(resp_data).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        try:
            server = socketserver.TCPServer((host, port), _WebhookHandler)
            server.allow_reuse_address = True
            self._webhook_server = server
        except Exception as e:
            logger.error("Failed to bind webhook server on %s:%d: %s", host, port, e)
            return

        def _serve():
            logger.info("Threat webhook server listening on %s:%d", host, port)
            try:
                server.serve_forever()
            except Exception:
                pass

        t = threading.Thread(target=_serve, name="ThreatStream-Webhook", daemon=True)
        self._webhook_thread = t
        t.start()

    def stop(self) -> None:
        """Stop background worker and webhook server."""
        self._running = False
        if self._webhook_server:
            try:
                self._webhook_server.shutdown()
                self._webhook_server.server_close()
            except Exception:
                pass
            self._webhook_server = None

    def get_status(self) -> dict[str, Any]:
        """Return comprehensive status information."""
        return {
            "running": self._running,
            "poll_interval_seconds": self.poll_interval,
            "last_poll_time": self.last_poll_time,
            "last_poll_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.last_poll_time)) if self.last_poll_time else "never",
            "total_polls": self.total_polls,
            "total_ingested_addresses": self.total_ingested_addresses,
            "total_ingested_selectors": self.total_ingested_selectors,
            "active_threat_addresses": len(self.threat_feed.blocked_addresses),
            "active_threat_selectors": len(self.threat_feed.blocked_selectors),
            "providers": [p.name for p in self.providers],
            "blocklist_path": str(self.blocklist_path) if self.blocklist_path else "in-memory",
            "last_sync_result": self.last_sync_result,
        }


# ==============================================================================
# Global Singleton & Helper Functions
# ==============================================================================

_DEFAULT_STREAM_SYNCER: ThreatStreamSyncer | None = None
_STREAM_LOCK = threading.Lock()


def get_default_threat_stream_syncer() -> ThreatStreamSyncer:
    """Retrieve or initialize the default global ThreatStreamSyncer."""
    global _DEFAULT_STREAM_SYNCER
    with _STREAM_LOCK:
        if _DEFAULT_STREAM_SYNCER is None:
            interval = int(os.getenv("SAFEGUARD_THREAT_POLL_INTERVAL", DEFAULT_POLL_INTERVAL_SECONDS))
            _DEFAULT_STREAM_SYNCER = ThreatStreamSyncer(poll_interval=interval)
        return _DEFAULT_STREAM_SYNCER


def start_threat_ingestion_daemon(
    interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    webhook_port: int | None = None,
    blocklist_path: str | Path | None = None,
) -> ThreatStreamSyncer:
    """Convenience function to start background polling and webhook ingestion in-process."""
    syncer = get_default_threat_stream_syncer()
    syncer.poll_interval = max(5, int(interval))
    if blocklist_path:
        syncer.blocklist_path = Path(blocklist_path)
    syncer.start_polling_worker()
    if webhook_port:
        syncer.start_webhook_server(port=webhook_port)
    return syncer


# ==============================================================================
# CLI Entrypoint
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hermes SafeGuard Live Web3 Threat Intelligence Ingestion Daemon"
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously as a background polling daemon (every 5 minutes by default)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"Polling interval in seconds (default: {DEFAULT_POLL_INTERVAL_SECONDS}s = 5m)",
    )
    parser.add_argument(
        "--webhook-port",
        type=int,
        default=None,
        help="Port to start live Web3 alert webhook server on (e.g. 8088)",
    )
    parser.add_argument(
        "--sync-once",
        action="store_true",
        help="Run a single threat intelligence synchronization pass and exit",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print current threat stream status and blocklist stats",
    )
    parser.add_argument(
        "--blocklist",
        type=str,
        default=None,
        help="Custom path to blocklist.json file",
    )
    parser.add_argument(
        "--test-alert",
        type=str,
        default=None,
        help="Simulate an incoming security alert for the specified address (e.g. 0x9999...)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    feed = get_default_threat_feed()
    if args.blocklist:
        feed.filepath = Path(args.blocklist)
        feed.load()

    syncer = ThreatStreamSyncer(
        threat_feed=feed,
        blocklist_path=args.blocklist,
        poll_interval=args.interval,
    )

    if args.test_alert:
        test_addr = args.test_alert.strip()
        alert = SecurityAlert(
            target=test_addr,
            category="malicious_contract",
            name="Simulated CLI Security Alert",
            description=f"Manual test alert ingested via CLI for 0x{normalize_address(test_addr)}",
            severity="CRITICAL",
            source="CLI_Test",
        )
        res = syncer.ingest_alerts([alert])
        print("🛡️ Simulated Alert Ingest Result:")
        print(json.dumps(res, indent=2))
        return 0

    if args.status:
        st = syncer.get_status()
        print("🛡️ Hermes SafeGuard Threat Stream Status:")
        print(json.dumps(st, indent=2))
        return 0

    if args.sync_once:
        print("🔄 Executing immediate multi-provider threat intelligence sync...")
        res = syncer.sync_once()
        print(json.dumps(res, indent=2))
        return 0

    if args.daemon or args.webhook_port:
        print(f"🚀 Starting Hermes SafeGuard Dynamic Threat Ingestion Service...")
        print(f"   • Poll Interval:   {args.interval}s (every {args.interval // 60}m {args.interval % 60}s)")
        print(f"   • Target Blocklist: {syncer.blocklist_path}")
        print(f"   • Active Feeds:    PeckShield, ScamSniffer, SlowMist")

        syncer.start_polling_worker()

        if args.webhook_port:
            syncer.start_webhook_server(port=args.webhook_port)
            print(f"   • Webhook Server:  http://0.0.0.0:{args.webhook_port}/webhook/<provider>")

        print("\nPress Ctrl+C to gracefully stop daemon.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down threat ingestion service...")
            syncer.stop()
            print("Stopped.")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

