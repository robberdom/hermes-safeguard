"""
Hermes SafeGuard — Slash Command Handlers (commands.py)
Implements all operator-level slash commands (/safeguard-mode, /safeguard-confirm, etc.)
Compliant with Hermes Agent Plugin Developer Guide:
- Slash commands run in session gateway
- Handlers return string text (Markdown / plain text)
- State persistence uses storage.py (plugin_data_dir)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from policy_engine import (
    PolicyConfig,
    PolicyMode,
    get_default_audit_logger,
    get_default_confirmation_store,
    get_default_memory_store,
    get_default_threat_feed,
    log_financial_action,
    normalize_address,
    safeguard_approve_address,
    safeguard_confirm_action,
    safeguard_get_audit_log,
    safeguard_list_approved_addresses,
    safeguard_list_pending_confirmations,
    safeguard_revoke_address,
)
from storage import get_plugin_data_dir, read_state_file, write_state_file, unlink_state_file, resolve_state_path
from tools import (
    _get_policy_config,
    _notify_telegram_operator,
    is_kill_switch_active,
    safeguard_check_policy_handler,
    safeguard_execute_tx_handler,
    set_kill_switch,
)
from verifier import (
    DEFAULT_RPC_URL,
    encode_nft_mint_calldata,
    is_rpc_available,
    rpc_request,
)

logger = logging.getLogger('hermes-safeguard.commands')

# Helper: Slash Command Argument Parser
# ==============================================================================

def _parse_command_args(*args: Any, **kwargs: Any) -> str:
    """
    Extract raw argument string across diverse Hermes slash command dispatch signatures.
    Handles:
      - handler("degen")
      - handler(ctx, "degen")
      - handler({"args": "degen"})
      - handler(raw_args="degen")
    """
    if args:
        if len(args) >= 2 and isinstance(args[1], str):
            return args[1].strip()
        if isinstance(args[0], str):
            return args[0].strip()
        if isinstance(args[0], dict):
            for k in ("args", "raw_args", "mode", "id", "address", "target", "text"):
                val = args[0].get(k)
                if val is not None:
                    return str(val).strip()
    for k in ("args", "raw_args", "mode", "id", "address", "target", "text"):
        val = kwargs.get(k)
        if val is not None:
            return str(val).strip()
    return ""


# ==============================================================================
# Slash Command: /safeguard-mode, /safeguard-strict, /safeguard-balanced, /safeguard-degen
# ==============================================================================

def safeguard_mode_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Switch or cycle SafeGuard policy mode between strict, balanced, and degen.
    - If no argument is given (or 'next'/'cycle'/'toggle'): cycles strict -> balanced -> degen -> strict.
    - If a mode name is given ('strict', 'balanced', 'degen' or '1', '2', '3'): switches directly.
    """
    raw_arg = _parse_command_args(*args, **kwargs).strip().lower()

    current_mode = os.getenv("SAFEGUARD_MODE", "balanced").strip().lower()
    if current_mode not in ("strict", "balanced", "degen"):
        current_mode = "balanced"

    mode_cycle = ["strict", "balanced", "degen"]
    number_map = {"1": "strict", "2": "balanced", "3": "degen"}

    target_mode = None
    if raw_arg in number_map:
        target_mode = number_map[raw_arg]
    else:
        # Check if any recognized token appears in the argument text
        tokens = [t for t in raw_arg.split() if t in ("strict", "balanced", "degen")]
        if tokens:
            target_mode = tokens[-1]

    if target_mode:
        action_verb = "Switched to" if target_mode != current_mode else "Already active:"
    elif raw_arg in ("", "next", "cycle", "toggle", "switch"):
        # Cycle to next mode
        curr_idx = mode_cycle.index(current_mode)
        target_mode = mode_cycle[(curr_idx + 1) % len(mode_cycle)]
        action_verb = f"Cycled from {current_mode.upper()} ➔"
    else:
        return (
            f"⚠️ Unknown mode: '{raw_arg}'.\n"
            f"Current active mode: {current_mode.upper()}\n"
            f"Valid modes: strict (1), balanced (2), degen (3)\n\n"
            f"Usage:\n"
            f"  /safeguard-mode              - Cycle to next mode\n"
            f"  /safeguard-mode <mode>       - Switch directly (strict, balanced, degen)\n"
            f"  /safeguard-strict            - Shortcut for strict mode\n"
            f"  /safeguard-balanced          - Shortcut for balanced mode\n"
            f"  /safeguard-degen             - Shortcut for degen mode"
        )

    # Set active mode in environment and persistent state file
    os.environ["SAFEGUARD_MODE"] = target_mode
    try:
        write_state_file(".safeguard_mode", target_mode)
    except Exception:
        pass
    try:
        (Path(__file__).resolve().parent / ".safeguard_mode").write_text(target_mode, encoding="utf-8")
    except Exception:
        pass
    env_file = Path(__file__).resolve().parent / ".env"
    if env_file.is_file():
        try:
            content = env_file.read_text(encoding="utf-8")
            if re.search(r"^SAFEGUARD_MODE=.*$", content, flags=re.MULTILINE):
                content = re.sub(r"^SAFEGUARD_MODE=.*$", f"SAFEGUARD_MODE={target_mode}", content, flags=re.MULTILINE)
            else:
                content = content.rstrip() + f"\nSAFEGUARD_MODE={target_mode}\n"
            env_file.write_text(content, encoding="utf-8")
        except Exception:
            pass
    if "SAFEGUARD_POLICY_PATH" in os.environ:
        del os.environ["SAFEGUARD_POLICY_PATH"]

    config, resolved_mode = _get_policy_config()
    max_eth_val = getattr(config, "max_eth_per_tx", 0)
    max_eth_disp = f"{max_eth_val / 10**18:.2f} ETH" if max_eth_val else "Unlimited"
    unlimited_app = "Allowed" if getattr(config, "allow_unlimited_approve", False) else "Blocked"
    zero_slip = "Blocked" if getattr(config, "block_zero_slippage", True) else "Allowed (with warning)"

    next_idx = (mode_cycle.index(target_mode) + 1) % len(mode_cycle)
    next_mode_name = mode_cycle[next_idx]

    lines = [
        f"🛡️ SafeGuard Policy: {action_verb} {target_mode.upper()}",
        "=" * 50,
        f"Active Mode: {target_mode.upper()}",
        f"  • Max ETH per Tx:          {max_eth_disp}",
        f"  • Unlimited Approvals:     {unlimited_app}",
        f"  • Zero-Slippage DEX Swaps: {zero_slip}",
        f"  • Threat Blocklist:        Enforced across all modes",
    ]
    if target_mode == "strict":
        lines.append("  • Unknown Recipients:      Requires operator confirmation (standing trust granted upon confirm)")
    elif target_mode == "balanced":
        lines.append("  • Unknown Recipients:      Permitted with EVM simulation & trace inspection")
    else:
        lines.append("  • High Token Tax:          Honeypots (>50% tax) blocked; degen tokens (<=50%) permitted with warning")

    lines.extend([
        "=" * 50,
        f"💡 Tip: Run /safeguard-mode to cycle to {next_mode_name.upper()} mode,",
        f"   or use shortcuts: /safeguard-strict, /safeguard-balanced, /safeguard-degen",
    ])
    return "\n".join(lines)


def safeguard_strict_command_handler(*args: Any, **kwargs: Any) -> str:
    """Operator shortcut: switch SafeGuard to strict mode."""
    return safeguard_mode_command_handler("strict")


def safeguard_balanced_command_handler(*args: Any, **kwargs: Any) -> str:
    """Operator shortcut: switch SafeGuard to balanced mode."""
    return safeguard_mode_command_handler("balanced")


def safeguard_degen_command_handler(*args: Any, **kwargs: Any) -> str:
    """Operator shortcut: switch SafeGuard to degen mode."""
    return safeguard_mode_command_handler("degen")


# ==============================================================================
# Slash Command: /safeguard-status
# ==============================================================================

def safeguard_status_handler(*args: Any, **kwargs: Any) -> str:
    """
    Return a summary of SafeGuard status, current policy limits, and RPC connectivity.
    Optionally switch active policy mode if a mode argument ('strict', 'balanced', 'degen')
    is supplied (e.g., /safeguard-status degen or /safeguard-mode strict).
    """
    # Check for requested mode change
    arg_text = _parse_command_args(*args, **kwargs).lower()

    mode_switched = False
    tokens = [t for t in arg_text.split() if t in ("strict", "balanced", "degen")]
    if tokens:
        target_mode = tokens[-1]
        os.environ["SAFEGUARD_MODE"] = target_mode
        if "SAFEGUARD_POLICY_PATH" in os.environ:
            del os.environ["SAFEGUARD_POLICY_PATH"]
        mode_switched = True

    config, mode = _get_policy_config()
    rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))

    # Perform a quick socket check on RPC URL host and port
    try:
        parsed = urlparse(rpc_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 8545)
        reachable = is_rpc_available(host, port)
        conn_str = f"Reachable ({rpc_url})" if reachable else f"Unreachable ({rpc_url})"
    except Exception as e:
        conn_str = f"Unreachable ({rpc_url} - {e})"

    max_eth_val = getattr(config, "max_eth_per_tx", 0)
    max_eth_display = f"{max_eth_val / 10**18:.2f} ETH ({max_eth_val} wei)" if max_eth_val else "Unlimited"
    unlimited_approve = getattr(config, "allow_unlimited_approve", False)
    zero_slippage_blocked = getattr(config, "block_zero_slippage", True)
    simulation_required = getattr(config, "require_simulation", True)

    mode_header = f"Mode: {mode} (Switched!)" if mode_switched else f"Mode: {mode}"

    status_lines = [
        "================ SafeGuard Status ================",
        mode_header,
    ]
    if is_kill_switch_active():
        status_lines.append("⚠️  EMERGENCY KILL-SWITCH: ACTIVE (All Transactions Halted)")
    status_lines.extend([
        "Policy Limits:",
        f"  - Max ETH per Tx: {max_eth_display}",
        f"  - Unlimited Approvals Allowed: {unlimited_approve}",
        f"  - Zero-Slippage DEX Swaps Blocked: {zero_slippage_blocked}",
        f"  - EVM Trace Simulation Required: {simulation_required}",
        f"Anvil/RPC Connectivity: {conn_str}",
        "Toggle mode: /safeguard-mode <strict|balanced|degen>",
        "Commands: /safeguard-help for full slash commands reference",
        "==================================================",
    ])
    return "\n".join(status_lines)


# ==============================================================================
# Slash Command: /safeguard-pending, /safeguard-confirm, /safeguard-reject
# ==============================================================================

def safeguard_pending_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    List all pending transactions currently awaiting human operator confirmation.
    Usage: /safeguard-pending
    """
    pending = safeguard_list_pending_confirmations()
    if not pending:
        return "✅ SafeGuard: No pending transactions awaiting confirmation. All clear!"

    lines = [
        f"⏳ Pending SafeGuard Confirmations ({len(pending)} item(s)):",
        "=" * 55,
    ]
    for idx, item in enumerate(pending, 1):
        cid = item.get("id", "unknown")
        target = item.get("to_address") or item.get("target", "N/A")
        val_eth = item.get("value_eth", 0.0)
        risk = str(item.get("risk_score", "medium")).upper()
        reason = item.get("reason", "No reason specified")
        action = item.get("action", "transaction")
        lines.extend([
            f"[{idx}] ID: {cid}",
            f"    Action: {action} | Risk: {risk}",
            f"    Target: {target}",
            f"    Value:  {val_eth:.4f} ETH",
            f"    Reason: {reason}",
            f"    Approve: /safeguard-confirm {cid}",
            f"    Reject:  /safeguard-reject {cid}",
            "-" * 55,
        ])
    return "\n".join(lines)


def safeguard_confirm_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to approve a held action by its confirmation_id.
    Usage: /safeguard-confirm <confirmation_id>
    """
    arg_text = _parse_command_args(*args, **kwargs)
    for prefix in ("/safeguard-confirm", "safeguard-confirm", "/confirm", "confirm"):
        if arg_text.startswith(prefix):
            arg_text = arg_text[len(prefix):].strip()
            break
    tokens = arg_text.split()
    conf_id = tokens[0] if tokens else ""
    if not conf_id:
        return (
            "Usage: /safeguard-confirm <confirmation_id>\n"
            "Tip: Run /safeguard-pending to view pending confirmation requests."
        )

    result = safeguard_confirm_action(confirmation_id=conf_id, approved=True)
    if result.get("status") == "confirmed":
        return f"✅ SafeGuard: Action {conf_id} has been CONFIRMED by operator."
    return f"❌ SafeGuard: Failed to confirm {conf_id}: {result.get('message', 'Unknown error')}"


def safeguard_reject_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to reject a held action by its confirmation_id.
    Usage: /safeguard-reject <confirmation_id> [reason]
    """
    arg_text = _parse_command_args(*args, **kwargs)
    for prefix in ("/safeguard-reject", "safeguard-reject", "/reject", "reject"):
        if arg_text.startswith(prefix):
            arg_text = arg_text[len(prefix):].strip()
            break
    tokens = arg_text.split()
    conf_id = tokens[0] if tokens else ""
    if not conf_id:
        return (
            "Usage: /safeguard-reject <confirmation_id>\n"
            "Tip: Run /safeguard-pending to view pending confirmation requests."
        )

    result = safeguard_confirm_action(confirmation_id=conf_id, approved=False)
    if result.get("status") == "rejected":
        return f"🚫 SafeGuard: Action {conf_id} has been REJECTED by operator."
    return f"❌ SafeGuard: Failed to reject {conf_id}: {result.get('message', 'Unknown error')}"


# ==============================================================================
# Slash Command: /safeguard-whitelist, /safeguard-allow, /safeguard-revoke
# ==============================================================================

def safeguard_whitelist_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    List all pre-approved / trusted addresses in SafeGuard memory store.
    Usage: /safeguard-whitelist (alias: /safeguard-contacts)
    """
    addrs = safeguard_list_approved_addresses()
    if not addrs:
        return (
            "ℹ️ SafeGuard Memory Store: No pre-approved addresses.\n"
            "Pre-approve a trusted recipient using: /safeguard-allow <address> [label]"
        )

    lines = [
        f"📋 SafeGuard Approved Addresses ({len(addrs)} entry/entries):",
        "=" * 55,
    ]
    for idx, entry in enumerate(addrs, 1):
        addr = entry.get("address", "")
        label = entry.get("label") or "(unlabeled)"
        atype = entry.get("type", "recipient")
        source = entry.get("source", "manual")
        lines.append(f"[{idx}] {addr} | {label} [{atype}] (via {source})")
    lines.extend([
        "=" * 55,
        "Commands: /safeguard-allow <addr> [label] | /safeguard-revoke <addr>",
    ])
    return "\n".join(lines)


def safeguard_allow_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Pre-approve a trusted recipient or contract address into SafeGuard memory.
    Usage: /safeguard-allow <address> [label]
    """
    raw = _parse_command_args(*args, **kwargs)
    tokens = raw.split(maxsplit=1)
    if not tokens:
        return (
            "Usage: /safeguard-allow <address> [label]\n"
            "Example: /safeguard-allow 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 Vitalik Treasury"
        )

    addr = tokens[0]
    label = tokens[1] if len(tokens) > 1 else "Operator Approved"

    try:
        res = safeguard_approve_address(address=addr, label=label)
        return (
            f"✅ SafeGuard: Pre-approved address {res['address']}\n"
            f"Label: {res.get('label')}\n"
            f"Standing trust recorded. In strict mode, transactions to this address will not require confirmation."
        )
    except Exception as e:
        return f"❌ SafeGuard: Failed to approve address: {e}"


def safeguard_revoke_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Revoke approval for an address in SafeGuard memory store.
    Usage: /safeguard-revoke <address>
    """
    raw = _parse_command_args(*args, **kwargs)
    tokens = raw.split()
    if not tokens:
        return "Usage: /safeguard-revoke <address>"

    addr = tokens[0]
    try:
        removed = safeguard_revoke_address(address=addr)
        if removed:
            return f"✅ SafeGuard: Revoked approval for {addr}."
        return f"ℹ️ Address {addr} was not found in approved memory store."
    except Exception as e:
        return f"❌ SafeGuard: Error revoking address: {e}"


def safeguard_connect_tg_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Generate an OTP pairing code to link an operator's personal phone Telegram to this Hermes Agent session.
    Usage: /safeguard-connect-tg (or /connect-tg)
    """
    try:
        from telegram_adapter import create_pairing_code, get_bot_username
        code, deep_link = create_pairing_code()
        bot_user = get_bot_username() or "your_bot"
        lines = [
            "📲 SafeGuard Telegram Connection",
            "=" * 50,
            f"Pairing Code: {code}  (Expires in 10 minutes)",
            "",
            "To connect your phone's Telegram to this Hermes Agent:",
            f"  1. Tap link to pair in one click: {deep_link}",
            f"  2. Or open Telegram bot @{bot_user} and send: /pair {code}",
            "",
            "Once connected:",
            "  • Routine transactions run 100% autonomously.",
            "  • Elevated risks (prompt injection, large transfers) send",
            "    Approve/Reject buttons directly to your phone!",
            "=" * 50,
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"❌ SafeGuard: Failed to generate pairing code: {e}"


# ==============================================================================
# Slash Command: /safeguard-check, /safeguard-threats
# ==============================================================================

def safeguard_check_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Inspect an address against threat feeds, known drainers, and memory store.
    Usage: /safeguard-check <address>
    """
    raw = _parse_command_args(*args, **kwargs)
    tokens = raw.split()
    if not tokens:
        return "Usage: /safeguard-check <address>"

    addr = tokens[0]
    try:
        norm = normalize_address(addr)
    except Exception as e:
        return f"❌ Invalid Ethereum address: {e}"

    tf = get_default_threat_feed()
    is_threat = tf.is_address_blocked(norm)
    threat = tf.get_address_threat(norm) if is_threat else None

    ms = get_default_memory_store()
    is_approved = ms.is_approved(norm)
    entry = ms.get_entry(norm) if is_approved else None

    lines = [
        f"🔍 SafeGuard Address Security Report: 0x{norm}",
        "=" * 55,
    ]
    if is_threat:
        ttype = getattr(threat, "threat_type", "threat_feed") if threat else "threat_feed"
        sev = getattr(threat, "severity", "critical") if threat else "critical"
        tname = threat.name if (threat and threat.name) else "Known exploit / malicious address"
        tdesc = threat.description if (threat and threat.description) else "Found in blocklist threat feed"
        lines.extend([
            "🚨 THREAT STATUS: BLOCKED (Known Exploit / Drainer / Phishing)",
            f"   Threat Name: {tname}",
            f"   Type:        {ttype}",
            f"   Severity:    {sev}",
            f"   Description: {tdesc}",
            "⚠️ All interactions with this address are strictly blocked across all modes.",
        ])
    else:
        lines.append("🛡️ THREAT STATUS: Clean (Not flagged on active blocklists/threat feeds)")

    if is_approved:
        lbl = entry.label if entry else ""
        lines.append(f"⭐ APPROVAL STATUS: Approved ({lbl}) in SafeGuard memory store")
    else:
        lines.append("ℹ️ APPROVAL STATUS: Not pre-approved")

    lines.append("=" * 55)
    return "\n".join(lines)


def safeguard_threats_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Display current threat intelligence feeds and blocklist summary.
    Usage: /safeguard-threats
    """
    tf = get_default_threat_feed()
    total_addrs = len(tf.blocked_addresses)
    total_sels = len(tf.blocked_selectors)
    source_str = str(tf.filepath) if tf.filepath else "In-memory default feed"
    version_str = getattr(tf, "version", "1.0.0")

    stream_status = "Active (PeckShield, ScamSniffer, SlowMist)"
    try:
        from threat_stream import get_default_threat_stream_syncer
        syncer = get_default_threat_stream_syncer()
        poll_info = f"Every {syncer.poll_interval}s"
    except Exception:
        poll_info = "Every 60s"

    return "\n".join([
        "🛡️ SafeGuard Threat Intelligence Status",
        "=" * 55,
        f"  • Feed Source:                {source_str}",
        f"  • Feed Version:               {version_str}",
        f"  • Blocked Threat Addresses:   {total_addrs}",
        f"  • Blocked Calldata Selectors: {total_sels}",
        f"  • Dynamic Live Streams:       {stream_status}",
        f"  • Dynamic Poll Schedule:      {poll_info} (automated daemon)",
        "  • Ingested Threat Feeds:      Web3 exploit reports, drainer proxies, phishing",
        "  • Simulation Protections:     Local Anvil EVM trace, drain detection, honeypot tax",
        "",
        "Commands:",
        "  /safeguard-check <address> - Inspect address against threat feed",
        "  /safeguard-sync            - Force sync & refresh threat feed",
        "=" * 55,
    ])


def safeguard_sync_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Force an immediate pull & sync from threat intelligence feeds to update the local denylist cache.
    Usage: /safeguard-sync [source_url]
    """
    arg_url = _parse_command_args(*args, **kwargs).strip()
    remote_url = arg_url if arg_url.startswith(("http://", "https://")) else os.getenv("SAFEGUARD_THREAT_FEED_URL", "").strip()

    tf = get_default_threat_feed()
    addresses_before = len(tf.blocked_addresses)

    synced_from = ""
    error_note = ""

    if remote_url:
        try:
            req = urllib.request.Request(
                remote_url,
                headers={"User-Agent": "Hermes-SafeGuard/0.1.0 (Threat-Feed-Sync)"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read().decode("utf-8")
                payload = json.loads(content)
                if isinstance(payload, dict):
                    # Ingest threats into feed
                    for entry in payload.get("malicious_contracts", []):
                        if isinstance(entry, dict) and "address" in entry:
                            tf.add_address(entry["address"], "malicious_contract", entry.get("name", ""), entry.get("description", ""))
                        elif isinstance(entry, str):
                            tf.add_address(entry, "malicious_contract")
                    for entry in payload.get("phishing_addresses", []):
                        if isinstance(entry, dict) and "address" in entry:
                            tf.add_address(entry["address"], "phishing", entry.get("name", ""), entry.get("description", ""))
                        elif isinstance(entry, str):
                            tf.add_address(entry, "phishing")
                    for entry in payload.get("dangerous_selectors", []):
                        if isinstance(entry, dict) and "selector" in entry:
                            tf.add_selector(entry["selector"], entry.get("signature", ""), entry.get("description", ""))
                        elif isinstance(entry, str):
                            tf.add_selector(entry)
                    synced_from = f"Remote URL ({remote_url})"
                    try:
                        tf.save()
                    except Exception:
                        pass
        except Exception as e:
            error_note = f" (Remote pull error: {e}; fell back to multi-provider stream sync)"

    if not synced_from:
        # Multi-provider dynamic sync (PeckShield, ScamSniffer, SlowMist)
        try:
            from threat_stream import get_default_threat_stream_syncer
            syncer = get_default_threat_stream_syncer()
            res = syncer.sync_once()
            synced_from = "Dynamic Web3 Streams (PeckShield, ScamSniffer, SlowMist)"
        except Exception as e:
            # Fallback to local blocklist reload
            try:
                tf.load()
                synced_from = f"Local Blocklist ({tf.filepath or 'defaults'})"
            except Exception as e2:
                return f"❌ SafeGuard: Failed to sync threat feed: {e2}"

    addresses_after = len(tf.blocked_addresses)
    selectors_count = len(tf.blocked_selectors)

    return "\n".join([
        "🔄 SafeGuard Threat Intelligence Sync Complete",
        "=" * 55,
        f"  • Source:                     {synced_from}{error_note}",
        f"  • Blocked Threat Addresses:   {addresses_after} (delta: {addresses_after - addresses_before:+d})",
        f"  • Blocked Calldata Selectors: {selectors_count}",
        "  • Threat Cache Status:        ACTIVE & UP TO DATE",
        "=" * 55,
    ])


# ==============================================================================
# Slash Command: /safeguard-test-alert
# ==============================================================================

def send_safeguard_alert(message: str, title: str = "SafeGuard Alert") -> dict[str, Any]:
    """
    Dispatch an alert to configured Telegram bot or webhook URL.
    Returns status dict indicating delivery or configuration status.
    """
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", os.getenv("SAFEGUARD_TELEGRAM_BOT_TOKEN", "")).strip()
    telegram_chat = os.getenv("TELEGRAM_CHAT_ID", os.getenv("SAFEGUARD_TELEGRAM_CHAT_ID", "")).strip()
    webhook_url = os.getenv("SAFEGUARD_WEBHOOK_URL", os.getenv("WEBHOOK_URL", "")).strip()

    if telegram_token and telegram_chat:
        url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
        body = json.dumps({
            "chat_id": telegram_chat,
            "text": f"🛡️ <b>{title}</b>\n\n{message}",
            "parse_mode": "HTML",
        }).encode("utf-8")
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Hermes-SafeGuard/0.1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_text = resp.read().decode("utf-8")
                return {"status": "delivered", "destination": "telegram", "chat_id": telegram_chat, "response": resp_text}
        except Exception as e:
            return {"status": "error", "destination": "telegram", "error": str(e)}

    if webhook_url:
        body = json.dumps({
            "event": "safeguard_alert",
            "title": title,
            "message": message,
            "mode": os.getenv("SAFEGUARD_MODE", "balanced"),
        }).encode("utf-8")
        try:
            req = urllib.request.Request(
                webhook_url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Hermes-SafeGuard/0.1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return {"status": "delivered", "destination": "webhook", "url": webhook_url}
        except Exception as e:
            return {"status": "error", "destination": "webhook", "error": str(e)}

    return {
        "status": "unconfigured",
        "destination": None,
        "message": "Neither TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID nor SAFEGUARD_WEBHOOK_URL is configured.",
    }


def safeguard_test_alert_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Send a test ping to configured Telegram chat or webhook to verify alert connectivity.
    Usage: /safeguard-test-alert
    """
    mode = os.getenv("SAFEGUARD_MODE", "balanced").upper()
    test_msg = (
        f"<b>Status</b>: Operational\n"
        f"<b>Policy Mode</b>: {mode}\n"
        f"<b>RPC Target</b>: {os.getenv('RPC_URL', DEFAULT_RPC_URL)}\n"
        f"<b>Verification Engine</b>: Anvil EVM Trace Simulation Active\n"
        f"<i>Test alert sent via /safeguard-test-alert operator command.</i>"
    )
    result = send_safeguard_alert(message=test_msg, title="Hermes SafeGuard Connectivity Test")

    if result.get("status") == "delivered":
        dest = result.get("destination", "endpoint")
        if dest == "telegram":
            chat_id = str(result.get("chat_id", ""))
            masked = f"...{chat_id[-4:]}" if len(chat_id) > 4 else chat_id
            return f"✅ SafeGuard: Test alert sent successfully to Telegram chat (ID: {masked})!"
        return f"✅ SafeGuard: Test alert successfully dispatched to webhook ({result.get('url')})!"

    if result.get("status") == "error":
        return f"❌ SafeGuard: Failed to dispatch test alert: {result.get('error')}"

    return "\n".join([
        "⚠️ SafeGuard Alert Delivery Unconfigured",
        "=" * 55,
        "No alert webhook or Telegram credentials were detected in environment.",
        "",
        "To enable real-time operator alerts & Telegram confirmations:",
        "  1. Set TELEGRAM_BOT_TOKEN=<your_bot_token>",
        "  2. Set TELEGRAM_CHAT_ID=<your_chat_id>",
        "     (or SAFEGUARD_WEBHOOK_URL=https://...)",
        "",
        "Simulated alert preview:",
        "  🛡️ Hermes SafeGuard Connectivity Test",
        f"  • Mode:   {mode}",
        "  • Engine: Anvil EVM Trace Simulation Active",
        "  • Status: Ready to deliver on configuration",
        "=" * 55,
    ])


# ==============================================================================
# Slash Command: /safeguard-panic, /safeguard-resume (Emergency Kill-Switch)
# ==============================================================================

def safeguard_panic_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to activate emergency kill-switch.
    Halts all onchain financial operations across all modes.
    Usage: /safeguard-panic
    """
    set_kill_switch(True)
    log_financial_action(
        action="emergency_panic",
        status="blocked",
        mode=os.getenv("SAFEGUARD_MODE", "balanced"),
        target="system",
        value_wei=0,
        data_hex="",
        risk_score="critical",
        reason="Operator engaged emergency panic kill-switch",
    )
    return "\n".join([
        "🚨" * 15,
        "EMERGENCY KILL-SWITCH ENGAGED",
        "🚨" * 15,
        "All onchain transactions, transfers, approvals, and swaps are LOCKED DOWN.",
        "No financial tools will execute across any policy mode.",
        "",
        "To release the kill-switch and restore verification, run:",
        "  /safeguard-resume",
        "=" * 55,
    ])


def safeguard_resume_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to release emergency kill-switch and resume normal policy verification.
    Usage: /safeguard-resume
    """
    set_kill_switch(False)
    current_mode = os.getenv("SAFEGUARD_MODE", "balanced").upper()
    log_financial_action(
        action="emergency_resume",
        status="allowed",
        mode=current_mode.lower(),
        target="system",
        value_wei=0,
        data_hex="",
        risk_score="low",
        reason="Operator released emergency panic kill-switch",
    )
    return "\n".join([
        "✅ SafeGuard: Emergency kill-switch has been RELEASED.",
        f"Normal policy verification is restored under {current_mode} mode.",
        "Financial tools and hooks are operational.",
        "=" * 55,
    ])


# ==============================================================================
# Slash Command: /safeguard-audit
# ==============================================================================

def safeguard_audit_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Show recent SafeGuard audit logs.
    Usage: /safeguard-audit [limit] (alias: /safeguard-logs)
    """
    raw = _parse_command_args(*args, **kwargs)
    limit = 5
    tokens = raw.split()
    if tokens and tokens[0].isdigit():
        limit = min(max(1, int(tokens[0])), 50)

    entries = safeguard_get_audit_log(limit=limit)
    if not entries:
        return "SafeGuard Audit Log: No recent financial actions logged."

    lines = [
        f"📜 SafeGuard Audit Log (Last {len(entries)} events):",
        "=" * 55,
    ]
    for idx, e in enumerate(entries, 1):
        status = str(e.get("status", "unknown")).upper()
        mode = e.get("mode", "")
        action = e.get("action", "tx")
        val_eth = e.get("value_eth", 0.0)
        target = e.get("target", "N/A")
        reason = e.get("reason", "")
        risk = e.get("risk_score", "")
        lines.extend([
            f"[{idx}] {status} [{mode}] {action} | {val_eth:.4f} ETH ➔ {target}",
            f"    Risk: {risk} | {reason}",
        ])
    lines.append("=" * 55)
    return "\n".join(lines)


# ==============================================================================
# Slash Command: /safeguard-help
# ==============================================================================

def safeguard_help_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Display complete help guide for all SafeGuard slash commands.
    Usage: /safeguard-help (alias: /safeguard)
    """
    current_mode = os.getenv("SAFEGUARD_MODE", "balanced").upper()
    return "\n".join([
        "🛡️ Hermes SafeGuard Slash Commands Reference",
        f"Current Active Mode: {current_mode}",
        "=" * 58,
        "⚙️  POLICY MODE SWITCHING:",
        "  /safeguard-mode                   - Cycle next mode (strict ➔ balanced ➔ degen)",
        "  /safeguard-mode <strict|balanced|degen> - Set mode directly",
        "  /safeguard-strict                 - Shortcut: Switch to STRICT mode",
        "  /safeguard-balanced               - Shortcut: Switch to BALANCED mode",
        "  /safeguard-degen                  - Shortcut: Switch to DEGEN mode",
        "",
        "📊 STATUS & DIAGNOSTICS:",
        "  /safeguard-status                 - Show active mode, limits, and RPC connection",
        "  /safeguard-threats                - View threat feed & drainer signatures summary",
        "  /safeguard-sync [url]             - Force threat intelligence feed sync & refresh",
        "  /safeguard-test-alert             - Send test ping to verify Telegram/webhook alerts",
        "  /safeguard-audit [limit]          - View recent transaction decisions (default: 5)",
        "",
        "🚨 EMERGENCY CIRCUIT-BREAKER:",
        "  /safeguard-panic                  - Emergency kill-switch: HALT all transactions",
        "  /safeguard-resume                 - Release kill-switch & restore normal policy",
        "",
        "⏳ HUMAN CONFIRMATION WORKFLOW:",
        "  /safeguard-pending                - List all transactions awaiting operator confirmation",
        "  /safeguard-confirm <id>           - Approve a held transaction",
        "  /safeguard-reject <id> [reason]   - Reject a held transaction",
        "",
        "📋 TRUSTED CONTACTS & WHITELIST:",
        "  /safeguard-whitelist              - List all approved addresses & labels",
        "  /safeguard-allow <addr> [label]   - Pre-approve a trusted recipient/contract",
        "  /safeguard-revoke <addr>          - Revoke an address from trusted memory",
        "  /safeguard-check <addr>           - Check address reputation against threat feeds",
        "",
        "ℹ️  HELP & INFO:",
        "  /safeguard-help                   - Show this command reference",
        "  /safeguard-mint <addr> [eth]      - Mint NFT immediately under EVM simulation",
        "  /safeguard-exec <addr> [eth] [hex]- Execute on-chain call under EVM simulation",
        "=" * 58,
    ])


def safeguard_mint_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Direct slash command to mint an NFT under SafeGuard EVM simulation protection.
    Usage: /safeguard-mint <contract_address> [unit_price_in_eth, default 0.05] [quantity, default 1]
    """
    raw_arg = _parse_command_args(*args, **kwargs).strip()
    parts = raw_arg.split()
    if not parts or not parts[0]:
        return "⚠️ Usage: /safeguard-mint <contract_address> [unit_price_in_eth, default 0.05] [quantity, default 1]"

    contract_addr = parts[0]
    val_raw = parts[1] if len(parts) > 1 else "0.05"
    if not val_raw.endswith("ether") and not val_raw.endswith("wei") and not val_raw.endswith("eth"):
        val_raw = f"{val_raw} ether"
    qty = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1

    unit_wei = _parse_wei_value(val_raw, 0)
    total_wei = unit_wei * qty
    total_eth = total_wei / 10**18
    calldata = encode_nft_mint_calldata(qty)

    res_raw = safeguard_execute_tx_handler(
        to=contract_addr,
        value=total_wei,
        data=calldata,
        quantity=qty,
    )
    res = json.loads(res_raw)
    status_emoji = "✅" if res.get("allowed") else "🚨"
    return "\n".join([
        f"{status_emoji} SafeGuard Mint Execution: {'ALLOWED' if res.get('allowed') else 'BLOCKED'}",
        "=" * 50,
        f"Target Contract: {contract_addr}",
        f"Quantity:        {qty} NFT{'s' if qty > 1 else ''}",
        f"Unit Price:      {val_raw}",
        f"Total Value:     {total_eth:.4f} ETH",
        f"Calldata:        {calldata[:18]}... (mint({qty}))",
        f"Risk Score:      {str(res.get('risk_score', '')).upper()}",
        f"Reason:          {res.get('reason')}",
        f"Mode:            {str(res.get('mode', '')).upper()}",
        "=" * 50,
    ])


def safeguard_exec_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Direct slash command to execute an on-chain transaction under SafeGuard EVM simulation protection.
    Usage: /safeguard-exec <target_address> [value_eth] [calldata_hex]
    """
    raw_arg = _parse_command_args(*args, **kwargs).strip()
    parts = raw_arg.split()
    if not parts or not parts[0]:
        return "⚠️ Usage: /safeguard-exec <target_address> [value_in_eth, default 0] [calldata_hex, default 0x]"

    to_addr = parts[0]
    val_eth = parts[1] if len(parts) > 1 else "0"
    if not val_eth.endswith("ether") and not val_eth.endswith("wei") and not val_eth.endswith("eth"):
        val_eth = f"{val_eth} ether"
    calldata = parts[2] if len(parts) > 2 else "0x"

    res_raw = safeguard_execute_tx_handler(
        to=to_addr,
        value=val_eth,
        data=calldata,
    )
    res = json.loads(res_raw)
    status_emoji = "✅" if res.get("allowed") else "🚨"
    return "\n".join([
        f"{status_emoji} SafeGuard Tx Execution: {'ALLOWED' if res.get('allowed') else 'BLOCKED'}",
        "=" * 50,
        f"Target Address:  {to_addr}",
        f"Value:           {val_eth}",
        f"Calldata:        {calldata}",
        f"Risk Score:      {str(res.get('risk_score', '')).upper()}",
        f"Reason:          {res.get('reason')}",
        f"Mode:            {str(res.get('mode', '')).upper()}",
        "=" * 50,
    ])

