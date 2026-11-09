"""
Hermes SafeGuard Plugin (__init__.py)

Policy engine and simulation guard for autonomous on-chain agent actions.
Intercepts financial tool calls, enforces strict / balanced / degen execution policies,
and verifies transactions via EVM simulation.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Ensure local imports work when loaded as a Hermes plugin directory
_PLUGIN_DIR = str(Path(__file__).resolve().parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from policy_engine import (
    APPROVE_SELECTOR,
    UINT256_MAX,
    PolicyConfig,
    PolicyMode,
    RiskScore,
    VerificationResult,
    _parse_wei_value,
    get_default_audit_logger,
    get_default_confirmation_store,
    get_default_memory_store,
    get_default_threat_feed,
    is_financial_tool,
    log_financial_action,
    normalize_address,
    safeguard_approve_address,
    safeguard_confirm_action,
    safeguard_get_audit_log,
    safeguard_list_approved_addresses,
    safeguard_list_pending_confirmations,
    safeguard_revoke_address,
    is_kill_switch_active,
    set_kill_switch,
)
from verifier import (
    DEFAULT_RPC_URL,
    ERC20_TRANSFER_SELECTOR,
    encode_address_word,
    encode_nft_mint_calldata,
    encode_uint256_word,
    is_rpc_available,
    verify_transaction,
)

# Tool names that are administrative / read-only and must NOT be blocked by pre_tool_call
SAFEGUARD_INTERNAL_TOOLS: set[str] = {
    "safeguard_check_policy",
    "safeguard_status",
    "safeguard_list_approved_addresses",
    "safeguard_approve_address",
    "safeguard_revoke_address",
    "safeguard_list_pending_confirmations",
    "safeguard_get_audit_log",
    "safeguard_search_threat_reports",
}

# Critical security files that agents must NEVER be allowed to modify
PROTECTED_BASENAMES: frozenset[str] = frozenset({
    "policy_engine.py",
    "verifier.py",
    "blocklist.json",
    "__init__.py",
    "plugin.yaml",
    "safeguardpolicy.sol",
    ".env",
    ".safeguard_pairing.json",
    ".safeguard_confirmations.json",
    ".safeguard_kill_switch",
})

# Tool-name verbs that can mutate a file or run arbitrary commands.
# Matched as whole tokens, so benign tools such as "run_tests" or "push_notification"
# are not caught by a substring like "run" or "sh".
_MUTATING_VERBS: frozenset[str] = frozenset({
    "write", "edit", "patch", "replace", "delete", "remove", "save", "modify",
    "create", "append", "touch", "update", "overwrite", "truncate", "put",
    "move", "copy", "rename", "chmod", "chown", "mkdir", "rmdir",
})
_COMMAND_VERBS: frozenset[str] = frozenset({
    "bash", "shell", "sh", "zsh", "cmd", "powershell", "terminal",
    "exec", "eval", "python", "python3", "perl", "ruby", "node", "subprocess",
})

# Emergency Kill-Switch State
_KILL_SWITCH_ACTIVE: bool = False


def is_kill_switch_active() -> bool:
    """True if operator has engaged emergency panic lockdown."""
    global _KILL_SWITCH_ACTIVE
    if _KILL_SWITCH_ACTIVE:
        return True
    return os.getenv("SAFEGUARD_KILL_SWITCH", "").strip().lower() in ("true", "1", "yes", "active")


def set_kill_switch(active: bool) -> None:
    """Engage or release the emergency kill-switch."""
    global _KILL_SWITCH_ACTIVE
    _KILL_SWITCH_ACTIVE = active
    if active:
        os.environ["SAFEGUARD_KILL_SWITCH"] = "true"
    else:
        if "SAFEGUARD_KILL_SWITCH" in os.environ:
            del os.environ["SAFEGUARD_KILL_SWITCH"]


def _iter_strings(obj: Any, depth: int = 0):
    """Yield every string nested inside a tool-argument structure."""
    if depth > 8:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _iter_strings(v, depth + 1)


def _references_protected_path(value: str) -> bool:
    """True if a string names a protected SafeGuard file or the policies directory."""
    raw = value.strip()
    if not raw or len(raw) > 4096:
        return False
    lowered = raw.replace("\\", "/").lower()
    # Match "policies" as a whole path word, so it is caught inside shell commands and
    # patch headers ("cd policies && ...", "Update File: policies/x.yaml") while not
    # matching unrelated identifiers such as "test_policies_fixtures".
    if re.search(r"(?<![a-z0-9_-])policies(?![a-z0-9_-])", lowered):
        return True
    parts = [p for p in lowered.split("/") if p not in ("", ".")]
    if parts and parts[-1] in PROTECTED_BASENAMES:
        return True
    # Catch protected filenames embedded in a larger string (e.g. shell/python one-liners)
    # without matching them as a substring of a longer identifier.
    if re.search(
        r"(?<![a-z0-9_])(?:policy_engine\.py|verifier\.py|blocklist\.json|__init__\.py|plugin\.yaml|safeguardpolicy\.sol|\.env|\.safeguard_pairing\.json|\.safeguard_confirmations\.json|\.safeguard_kill_switch)(?![a-z0-9_])",
        lowered,
    ):
        return True
    return False


def _is_policy_tampering_attempt(tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Detect if an agent tool call is attempting to alter SafeGuard policies or security code."""
    tokens = {t for t in re.split(r"[^a-z0-9]+", str(tool_name or "").lower()) if t}
    if not (tokens & _MUTATING_VERBS or tokens & _COMMAND_VERBS):
        return False

    for val in _iter_strings(tool_args if isinstance(tool_args, dict) else {}):
        if _references_protected_path(val):
            return True
    return False

# Keywords that indicate financial or on-chain execution intent in tool names
FINANCIAL_NAME_KEYWORDS: tuple[str, ...] = (
    "transfer",
    "approve",
    "swap",
    "mint",
    "send_tx",
    "sendtransaction",
    "send_transaction",
    "execute_tx",
    "executetx",
    "sign_transaction",
    "signtransaction",
    "wallet",
    "payout",
    "claim",
    "deposit",
    "withdraw",
    "call_contract",
    "pay",
    "bridge",
    "stake",
    "unstake",
    "lend",
    "borrow",
    "trade",
    "multicall",
    "eth_sendtransaction",
)


def _get_policy_config(mode: str | None = None, config: PolicyConfig | None = None) -> tuple[PolicyConfig, str]:
    """
    Resolve active PolicyConfig and mode string.
    Priority:
      1. Explicit config instance (if provided via host/kwargs)
      2. Explicit mode argument ('strict', 'balanced', 'degen')
      3. SAFEGUARD_POLICY_PATH environment variable (if mode not explicit)
      4. SAFEGUARD_MODE environment variable (default: 'balanced')
    """
    if config is not None:
        mode_str = config.mode.value if isinstance(config.mode, PolicyMode) else str(config.mode).lower()
        return config, mode_str
    if mode and str(mode).strip():
        mode_str = str(mode).strip().lower()
        if mode_str == "strict":
            return PolicyConfig.strict(), "strict"
        elif mode_str == "degen":
            return PolicyConfig.degen(), "degen"
        else:
            return PolicyConfig.balanced(), "balanced"

    policy_path = os.getenv("SAFEGUARD_POLICY_PATH")
    if policy_path and Path(policy_path).is_file():
        try:
            cfg = PolicyConfig.from_yaml(policy_path)
            mode_name = cfg.mode.value if isinstance(cfg.mode, PolicyMode) else str(cfg.mode).lower()
            return cfg, mode_name
        except Exception as e:
            print(f"SafeGuard Warning: Failed to load policy from {policy_path}: {e}")

    env_mode = os.getenv("SAFEGUARD_MODE", "balanced").strip().lower()
    if env_mode == "strict":
        return PolicyConfig.strict(), "strict"
    elif env_mode == "degen":
        return PolicyConfig.degen(), "degen"
    return PolicyConfig.balanced(), "balanced"


def _extract_tx_params(args: dict[str, Any], tool_name: str = "") -> tuple[str, int, str]:
    """
    Extract destination address, value in wei, and calldata hex from tool arguments.
    Supports flat arguments, nested structures (e.g. params[0], tx, transaction),
    and synthesizes standard calldata for high-level tool calls (approve, mint, transfer)
    if raw calldata was not explicitly provided.
    Fails closed on ambiguous multiple-transaction payloads.
    """
    target: dict[str, Any] = args
    if "params" in args and isinstance(args["params"], list):
        if len(args["params"]) > 1:
            raise ValueError("Ambiguous payload: multiple transaction entries in params")
        if args["params"] and isinstance(args["params"][0], dict):
            target = args["params"][0]
    elif "transaction" in args and isinstance(args["transaction"], dict):
        target = args["transaction"]
    elif "tx" in args and isinstance(args["tx"], dict):
        target = args["tx"]

    to_addr = str(
        target.get("to")
        or target.get("to_address")
        or target.get("target")
        or target.get("recipient")
        or target.get("contract")
        or target.get("contract_address")
        or target.get("token")
        or target.get("token_address")
        or ""
    ).strip()

    val_raw = target.get("value", target.get("value_wei", target.get("amount")))
    if val_raw is not None and val_raw != "":
        try:
            val_wei = _parse_wei_value(val_raw, 0)
        except (ValueError, TypeError):
            val_wei = -1
    else:
        val_wei = 0

    data_val = str(
        target.get("data")
        or target.get("data_hex")
        or target.get("calldata")
        or target.get("input")
        or ""
    ).strip()

    t_lower = tool_name.lower()

    # Synthesize standard calldata if absent and parameters indicate specific action.
    # A failed synthesis raises rather than substituting "0x": verifying a benign empty
    # payload while the real tool call executes something else would be a silent bypass.
    if not data_val or data_val in ("0x", "0X"):
        if "approve" in t_lower:
            spender = str(target.get("spender") or target.get("operator") or "").strip()
            if not spender:
                raise ValueError("approve call is missing a 'spender'/'operator' address")
            amt_raw = target.get("amount") or target.get("value")
            if str(amt_raw).lower() in ("unlimited", "max", "type(uint256).max"):
                amt_num = UINT256_MAX
            else:
                try:
                    amt_num = _parse_wei_value(amt_raw, 0)
                except (ValueError, TypeError):
                    amt_num = -1
            try:
                data_val = "0x" + APPROVE_SELECTOR + encode_address_word(spender).hex() + encode_uint256_word(amt_num).hex()
            except Exception as e:
                raise ValueError(f"unable to encode approve calldata: {e}") from e
        elif "mint" in t_lower:
            qty_raw = target.get("quantity") or target.get("amount") or 1
            try:
                qty_int = int(qty_raw)
            except Exception:
                qty_int = 1
            try:
                data_val = encode_nft_mint_calldata(qty_int)
            except Exception as e:
                raise ValueError(f"unable to encode mint calldata: {e}") from e
        elif "transfer" in t_lower and (target.get("token") or target.get("token_address")):
            # ERC-20 transfer: destination is the token contract, calldata encodes recipient + amount
            token_addr = str(target.get("token") or target.get("token_address") or "").strip()
            recipient = str(target.get("to") or target.get("recipient") or target.get("to_address") or "").strip()
            if not token_addr:
                raise ValueError("ERC-20 transfer is missing a token address")
            if not recipient:
                raise ValueError("ERC-20 transfer is missing a recipient address")
            to_addr = token_addr
            try:
                amt_num = _parse_wei_value(target.get("amount") or target.get("value"), 0)
            except (ValueError, TypeError):
                amt_num = -1
            try:
                data_val = "0x" + ERC20_TRANSFER_SELECTOR + encode_address_word(recipient).hex() + encode_uint256_word(amt_num).hex()
                val_wei = 0  # Native ETH value is 0 for ERC-20 transfer
            except Exception as e:
                raise ValueError(f"unable to encode ERC-20 transfer calldata: {e}") from e

    if not data_val:
        data_val = "0x"

    return to_addr, val_wei, data_val


def _is_financial_tool_call(tool_name: str, tool_args: dict[str, Any]) -> bool:
    """
    Conservatively determine if a tool invocation represents an on-chain financial action.
    """
    name_clean = str(tool_name or "").strip().lower()

    # Never intercept read-only/administrative SafeGuard tools
    if name_clean in SAFEGUARD_INTERNAL_TOOLS:
        return False

    # Check known financial tool names or keywords
    if is_financial_tool(name_clean) or any(kw in name_clean for kw in FINANCIAL_NAME_KEYWORDS):
        return True

    # Check argument pattern across flat arguments and nested tx/transaction/params structures
    candidates: list[dict[str, Any]] = [tool_args]
    if isinstance(tool_args.get("tx"), dict):
        candidates.append(tool_args["tx"])
    if isinstance(tool_args.get("transaction"), dict):
        candidates.append(tool_args["transaction"])
    if isinstance(tool_args.get("params"), list):
        for p in tool_args["params"]:
            if isinstance(p, dict):
                candidates.append(p)

    for c in candidates:
        to_val = str(
            c.get("to")
            or c.get("to_address")
            or c.get("target")
            or c.get("recipient")
            or c.get("contract")
            or c.get("token")
            or ""
        ).strip()
        has_eth_target = to_val.startswith("0x") and len(to_val) == 42
        has_tx_keys = any(
            k in c
            for k in ("value", "value_wei", "data", "data_hex", "calldata", "gas", "gas_price", "input", "amount")
        )
        if has_eth_target and has_tx_keys:
            return True

    return False


# ==============================================================================
# Tool Handlers
# ==============================================================================

def safeguard_check_policy_handler(*args: Any, **kwargs: Any) -> str:
    """
    Simulate and verify an on-chain transaction against SafeGuard policies without signing.
    Parameters: to (string), value (string or int, in wei), data (hex string, default "0x"),
                mode (optional string: "strict"|"balanced"|"degen", default from config or "balanced").
    Returns a JSON string containing at least:
      {"allowed": bool, "reason": str, "risk_score": str, "warning": str or null, "mode": str}
    """
    call_args: dict[str, Any] = {}
    if args:
        if isinstance(args[0], dict):
            call_args.update(args[0])
        elif isinstance(args[0], str):
            call_args["to"] = args[0]
            if len(args) > 1:
                call_args["value"] = args[1]
            if len(args) > 2:
                call_args["data"] = args[2]
            if len(args) > 3:
                call_args["mode"] = args[3]
    call_args.update(kwargs)
    if "params" in call_args and isinstance(call_args["params"], dict):
        call_args.update(call_args["params"])

    to_addr = str(call_args.get("to") or call_args.get("to_address") or "").strip()
    val_raw = call_args.get("value", 0)
    data_raw = str(call_args.get("data") or call_args.get("data_hex") or "0x").strip()

    # Read-only dry run: mode is operator-controlled. An agent-supplied mode would let it
    # obtain a self-served "allowed" verdict under a more permissive tier.
    config, resolved_mode = _get_policy_config()
    rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))

    if is_kill_switch_active():
        panic_msg = "SafeGuard Panic: Emergency kill-switch is ACTIVE. All onchain transactions are halted."
        log_financial_action(
            action="safeguard_check_policy", status="blocked", mode=resolved_mode,
            target=to_addr or "emergency_kill_switch", value_wei=_parse_wei_value(val_raw, 0),
            data_hex=data_raw, risk_score="critical", reason=panic_msg
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "reason": panic_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })

    if not to_addr:
        return json.dumps({
            "allowed": False,
            "reason": "SafeGuard: Missing required parameter 'to' address",
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })

    val_wei = _parse_wei_value(val_raw, 0)
    if not data_raw:
        data_raw = "0x"

    context = kwargs.get("context") or kwargs.get("messages") or call_args.get("context") or []
    conf_id = call_args.get("confirmation_id") or kwargs.get("confirmation_id")

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
            context=context,
            confirmation_id=conf_id,
        )
        risk_str = res.risk_score.value if hasattr(res.risk_score, "value") else str(res.risk_score).lower()
        out = {
            "allowed": bool(res.allowed),
            "reason": str(res.reason),
            "risk_score": risk_str,
            "warning": res.warning if res.warning else None,
            "mode": resolved_mode,
        }
        return json.dumps(out)
    except Exception as e:
        return json.dumps({
            "allowed": False,
            "reason": f"SafeGuard verification error (fail-closed): {str(e)}",
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })


def safeguard_execute_tx_handler(*args: Any, **kwargs: Any) -> str:
    """
    Verify and execute an on-chain transaction under SafeGuard policy protection.
    Always runs the full verification first. If allowed is False or risk is critical,
    returns a clear failure payload blocking execution and including the exact policy reason.
    If allowed, returns a success payload indicating SafeGuard approval.
    """
    call_args: dict[str, Any] = {}
    if args:
        if isinstance(args[0], dict):
            call_args.update(args[0])
        elif isinstance(args[0], str):
            call_args["to"] = args[0]
            if len(args) > 1:
                call_args["value"] = args[1]
            if len(args) > 2:
                call_args["data"] = args[2]
            if len(args) > 3:
                call_args["mode"] = args[3]
    call_args.update(kwargs)
    if "params" in call_args and isinstance(call_args["params"], dict):
        call_args.update(call_args["params"])

    to_addr = str(call_args.get("to") or call_args.get("to_address") or "").strip()
    val_raw = call_args.get("value", 0)
    data_raw = str(call_args.get("data") or call_args.get("data_hex") or "0x").strip()
    config, resolved_mode = _get_policy_config()
    rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))

    if is_kill_switch_active():
        panic_msg = "SafeGuard Panic: Emergency kill-switch is ACTIVE. All onchain transactions are halted."
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr or "emergency_kill_switch", value_wei=_parse_wei_value(val_raw, 0),
            data_hex=data_raw, risk_score="critical", reason=panic_msg
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "reason": panic_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })

    if not to_addr:
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "reason": "SafeGuard: Missing required parameter 'to' address",
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })

    val_wei = _parse_wei_value(val_raw, 0)
    if not data_raw:
        data_raw = "0x"

    context = kwargs.get("context") or kwargs.get("messages") or call_args.get("context") or []
    conf_id = call_args.get("confirmation_id") or kwargs.get("confirmation_id")

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
            context=context,
            confirmation_id=conf_id,
        )
        risk_str = res.risk_score.value if hasattr(res.risk_score, "value") else str(res.risk_score).lower()

        if getattr(res, "requires_confirmation", False):
            cid = getattr(res, "confirmation_id", "") or conf_id
            summary = getattr(res, "confirmation_summary", "") or res.reason
            _notify_telegram_operator(cid, summary, risk_score=risk_str, mode=resolved_mode)
            return json.dumps({
                "status": "requires_confirmation",
                "executed": False,
                "allowed": False,
                "requires_confirmation": True,
                "confirmation_id": cid,
                "confirmation_summary": summary,
                "reason": res.reason or "Transaction requires explicit operator confirmation",
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            })

        if not res.allowed or risk_str == "critical":
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "reason": res.reason or "Transaction blocked by SafeGuard policy",
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            })

        # Transaction passed all policy checks and EVM trace simulation.
        # Nothing is signed or broadcast here: the runtime signer owns that step.
        return json.dumps({
            "status": "success",
            "verified": True,
            "executed": False,
            "broadcast": False,
            "allowed": True,
            "message": "Transaction verified and approved for execution; broadcast payload prepared for runtime signer",
            "risk_score": risk_str,
            "warning": res.warning if res.warning else None,
            "mode": resolved_mode,
            "tx": {
                "to": to_addr,
                "value": str(val_wei),
                "data": data_raw,
                "gas": call_args.get("gas"),
                "gas_price": call_args.get("gas_price"),
            },
            "note": "Transaction simulation passed SafeGuard policies. Broadcast payload prepared for runtime signer.",
        })
    except Exception as e:
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "reason": f"SafeGuard verification exception (fail-closed): {str(e)}",
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })


def safeguard_confirm_action_handler(*args: Any, **kwargs: Any) -> str:
    """
    Python handler for programmatic confirmation (kept for test harness and direct calls).
    Not exposed as an agent tool to prevent agent self-approval.
    """
    call_args: dict[str, Any] = {}
    if args:
        if isinstance(args[0], dict):
            call_args.update(args[0])
        elif isinstance(args[0], str):
            call_args["confirmation_id"] = args[0]
            if len(args) > 1:
                call_args["approved"] = bool(args[1])
    call_args.update(kwargs)
    if "params" in call_args and isinstance(call_args["params"], dict):
        call_args.update(call_args["params"])

    conf_id = str(call_args.get("confirmation_id") or "").strip()
    approved = bool(call_args.get("approved", False))
    if not conf_id:
        return json.dumps({
            "status": "error",
            "message": "Missing required parameter 'confirmation_id'",
        })
    result = safeguard_confirm_action(confirmation_id=conf_id, approved=approved)
    return json.dumps(result, indent=2)


# ==============================================================================
# Telegram Operator Notification Helper
# ==============================================================================

def _notify_telegram_operator(
    conf_id: str,
    summary: str,
    risk_score: str = "high",
    mode: str = "balanced",
) -> bool:
    """
    If TELEGRAM_BOT_TOKEN and TELEGRAM_OPERATOR_CHAT_ID are configured in environment or .env,
    automatically send a real-time interactive alert with Approve/Reject buttons to the operator.
    Safe and non-blocking: fails silently if unconfigured or network is unavailable.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_OPERATOR_CHAT_ID", "").strip()
    if not chat_id:
        try:
            from telegram_adapter import get_operator_chat_id
            chat_id = get_operator_chat_id() or ""
        except Exception:
            pass
    if not token or not chat_id:
        return False

    try:
        from telegram_adapter import TelegramBot
        import html
        bot = TelegramBot(token)
        risk_emoji = "🚨" if risk_score.lower() == "critical" else "⚠️"
        safe_summary = html.escape(summary)
        text = (
            f"<b>{risk_emoji} SafeGuard [{mode.upper()}] Operator Approval Required</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>ID:</b> <code>{conf_id}</code>\n"
            f"<b>Risk Level:</b> <code>{risk_score.upper()}</code>\n\n"
            f"<b>Summary:</b>\n{safe_summary}\n\n"
            f"<i>Action held. Tap below or run /safeguard-confirm {conf_id} to approve.</i>"
        )
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve Transaction", "callback_data": f"approve:{conf_id}"},
                    {"text": "🚫 Reject", "callback_data": f"reject:{conf_id}"},
                ],
                [
                    {"text": "📋 View Details", "callback_data": f"details:{conf_id}"},
                ],
            ]
        }
        res = bot.send_message(chat_id, text, reply_markup=reply_markup)
        return bool(res.get("ok"))
    except Exception as e:
        logger.warning("SafeGuard: Telegram operator alert notification skipped: %s", e)
        return False


def _notify_telegram_event(title: str, details: str) -> bool:
    """
    Send an informational event alert to the paired Telegram operator.
    Safe and non-blocking: fails silently if unconfigured or network is unavailable.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_OPERATOR_CHAT_ID", "").strip()
    if not chat_id:
        try:
            from telegram_adapter import get_operator_chat_id
            chat_id = get_operator_chat_id() or ""
        except Exception:
            pass
    if not token or not chat_id:
        return False

    try:
        from telegram_adapter import TelegramBot
        bot = TelegramBot(token)
        text = f"<b>{title}</b>\n━━━━━━━━━━━━━━━━━━━━━━\n{details}"
        res = bot.send_message(chat_id, text)
        return bool(res.get("ok"))
    except Exception as e:
        logger.debug("SafeGuard: Telegram event notification skipped: %s", e)
        return False


# ==============================================================================
# Hook Handler: pre_tool_call
# ==============================================================================

def on_pre_tool_call(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """
    Hook evaluator for pre_tool_call events in Hermes Agent.
    Intercepts on-chain financial operations (transfers, approves, swaps, mints),
    extracts transaction parameters, and runs SafeGuard verification.
    """
    try:
        # Resolve tool name and arguments from various Hermes calling conventions
        tool_name = ""
        tool_args: dict[str, Any] = {}

        if len(args) >= 2:
            tool_name = str(args[0])
            tool_args = args[1] if isinstance(args[1], dict) else {}
            if isinstance(args[1], str):
                try:
                    tool_args = json.loads(args[1])
                except Exception:
                    tool_args = {}
        elif len(args) == 1:
            call_obj = args[0]
            if isinstance(call_obj, dict):
                tool_name = str(call_obj.get("name") or call_obj.get("tool") or call_obj.get("tool_name") or "")
                raw_args = call_obj.get("args") or call_obj.get("arguments") or call_obj.get("parameters") or {}
                tool_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            elif isinstance(call_obj, str):
                tool_name = call_obj
                tool_args = {}
            else:
                tool_name = str(getattr(call_obj, "name", "") or getattr(call_obj, "tool_name", "") or getattr(call_obj, "tool", ""))
                raw_args = getattr(call_obj, "args", {}) or getattr(call_obj, "arguments", {}) or getattr(call_obj, "parameters", {})
                tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})
        else:
            tool_name = str(kwargs.get("tool_name") or kwargs.get("name") or kwargs.get("tool") or "")
            raw_args = kwargs.get("tool_args") or kwargs.get("args") or kwargs.get("arguments") or kwargs.get("parameters") or {}
            tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})

        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except Exception:
                tool_args = {}

        # Mode is strictly operator-controlled via config or env; ignore agent-supplied mode arguments
        mode_override = kwargs.get("mode")
        config_override = kwargs.get("config")
        config, mode = _get_policy_config(mode_override, config=config_override)

        # Security barrier: Block any agent attempt to overwrite policy files or tamper with code
        if _is_policy_tampering_attempt(tool_name, tool_args):
            err_msg = "SafeGuard Security: Agent is strictly forbidden from modifying SafeGuard policy configuration, limits, or code."
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="local_policy_file", value_wei=0, data_hex="",
                risk_score="critical", reason=err_msg
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: Policy tampering attempt")
            return {
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "risk_score": "critical",
                "mode": mode,
            }

        # Emergency Kill-Switch: If active, hard-block ALL financial operations immediately
        if is_kill_switch_active() and _is_financial_tool_call(tool_name, tool_args):
            err_msg = "SafeGuard Panic: Emergency kill-switch is ACTIVE. All onchain transactions and financial operations are halted."
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="emergency_kill_switch", value_wei=0, data_hex="",
                risk_score="critical", reason=err_msg
            )
            print(f"SafeGuard [PANIC]: Intercepted '{tool_name}' -> BLOCKED: Emergency kill-switch active")
            return {
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "risk_score": "critical",
                "mode": mode,
            }

        # Conservative interception: only trigger on tools that appear to be financial
        if not _is_financial_tool_call(tool_name, tool_args):
            return {"action": "approve", "allowed": True, "message": "Non-financial tool permitted", "mode": mode}

        try:
            to_addr, val_wei, data_hex = _extract_tx_params(tool_args, tool_name)
        except ValueError as e:
            err_msg = f"SafeGuard: Rejected ambiguous or malformed transaction: {e}"
            return {
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "risk_score": "critical",
                "mode": mode,
            }

        if val_wei < 0:
            err_msg = "SafeGuard: Malformed or unparseable transaction amount."
            return {
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "risk_score": "high",
                "mode": mode,
            }

        rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))

        # Destination address is mandatory for intercepted on-chain transactions
        if not to_addr:
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="", value_wei=val_wei, data_hex=data_hex,
                risk_score="critical", reason="Missing destination address ('to')"
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: Missing destination address ('to')")
            return {
                "action": "block",
                "message": f"SafeGuard [{mode}] BLOCKED: Missing destination address ('to')",
                "reason": "Missing destination address ('to')",
                "risk_score": "critical",
                "mode": mode,
            }

        # Extract recent conversation or tool context strictly from host/system kwargs (never untrusted agent args)
        context = kwargs.get("context") or kwargs.get("messages") or []

        # Consume confirmation_id if supplied in retry
        active_conf_id = tool_args.get("confirmation_id") if isinstance(tool_args, dict) else None

        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_hex,
            config=config,
            rpc_url=rpc_url,
            context=context,
            confirmation_id=active_conf_id,
        )

        risk_str = res.risk_score.value if hasattr(res.risk_score, "value") else str(res.risk_score).lower()

        # Handle pending human confirmation workflows
        if getattr(res, "requires_confirmation", False):
            conf_id = getattr(res, "confirmation_id", "")
            summary = getattr(res, "confirmation_summary", "") or res.reason
            tg_notified = _notify_telegram_operator(conf_id, summary, risk_score=risk_str, mode=mode)
            tg_status = " (Interactive prompt dispatched to operator's Telegram)" if tg_notified else ""
            msg = (
                f"SafeGuard [{mode.upper()}] REQUIRES OPERATOR CONFIRMATION (ID: {conf_id}):\n"
                f"{summary}\n\n"
                f"Action is held for operator approval{tg_status}. Operator must approve via Telegram or run /safeguard-confirm {conf_id} in chat to approve, or /safeguard-reject {conf_id} to reject."
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> REQUIRES CONFIRMATION: ID {conf_id}{tg_status}")
            return {
                "action": "block",
                "message": msg,
                "reason": res.reason,
                "risk_score": risk_str,
                "requires_confirmation": True,
                "confirmation_id": conf_id,
                "confirmation_summary": summary,
                "mode": mode,
                "telegram_notified": tg_notified,
            }

        # Check for unambiguous fund drains
        is_drain = (
            risk_str == "critical"
            or any(kw in res.reason.lower() for kw in ("drain", "extortionate", "balance loss", "threat feed", "denylist", "blocklist", "sweeper"))
        )

        # Degen mode logic: check disallowed actions first before medium-risk warnings
        if mode == "degen":
            if not res.allowed or is_drain or risk_str == "critical":
                msg = f"SafeGuard [degen] BLOCKED: {res.reason}"
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> BLOCKED: {res.reason}")
                return {
                    "action": "block",
                    "message": msg,
                    "reason": res.reason,
                    "risk_score": risk_str,
                    "mode": mode,
                }
            elif risk_str == "medium":
                warn_text = res.warning or res.reason or "Medium-risk action permitted under degen mode"
                msg = f"SafeGuard [degen] WARNING: {warn_text}"
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> ALLOWED with warning: {warn_text}")
                return {
                    "action": "approve",
                    "allowed": True,
                    "message": msg,
                    "warning": warn_text,
                    "risk_score": "medium",
                    "mode": mode,
                }
            else:
                warn_msg = f" (Warning: {res.warning})" if res.warning else ""
                msg = f"SafeGuard [degen]: Transaction verified successfully.{warn_msg}"
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> ALLOWED")
                return {
                    "action": "approve",
                    "allowed": True,
                    "message": msg,
                    "warning": res.warning or None,
                    "risk_score": risk_str,
                    "mode": mode,
                }

        # Strict and Balanced modes: fail-closed on any disallowed policy result or critical risk
        if getattr(res, "requires_confirmation", False):
            cid = getattr(res, "confirmation_id", "") or conf_id
            summary = getattr(res, "confirmation_summary", "") or res.reason
            _notify_telegram_operator(cid, summary, risk_score=risk_str, mode=resolved_mode)
            return json.dumps({
                "status": "requires_confirmation",
                "executed": False,
                "allowed": False,
                "requires_confirmation": True,
                "confirmation_id": cid,
                "confirmation_summary": summary,
                "reason": res.reason or "Transaction requires explicit operator confirmation",
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            })

        if not res.allowed or risk_str == "critical":
            msg = f"SafeGuard [{mode}] BLOCKED: {res.reason or 'Transaction blocked by SafeGuard policy'}"
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: {res.reason}")
            return {
                "action": "block",
                "message": msg,
                "reason": res.reason,
                "risk_score": risk_str,
                "mode": mode,
            }

        warn_msg = f" (Warning: {res.warning})" if res.warning else ""
        msg = f"SafeGuard [{mode}]: Transaction verified successfully.{warn_msg}"
        print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> ALLOWED")
        return {
            "action": "approve",
            "allowed": True,
            "message": msg,
            "warning": res.warning or None,
            "risk_score": risk_str,
            "mode": mode,
        }

    except Exception as e:
        # Always fail closed on unhandled exceptions
        env_mode = os.getenv("SAFEGUARD_MODE", "balanced").strip().lower()
        err_msg = f"SafeGuard [{env_mode}] BLOCKED (fail-closed internal error): {str(e)}"
        print(err_msg)
        return {
            "action": "block",
            "message": err_msg,
            "reason": str(e),
            "risk_score": "critical",
            "mode": env_mode,
        }


# ==============================================================================
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

    # Set active mode in environment
    os.environ["SAFEGUARD_MODE"] = target_mode
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

    return "\n".join([
        "🛡️ SafeGuard Threat Intelligence Status",
        "=" * 55,
        f"  • Feed Source:                {source_str}",
        f"  • Feed Version:               {version_str}",
        f"  • Blocked Threat Addresses:   {total_addrs}",
        f"  • Blocked Calldata Selectors: {total_sels}",
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
        except Exception as e:
            error_note = f" (Remote pull error: {e}; fell back to local cache reload)"

    if not synced_from:
        # Reload from local file / default blocklist
        try:
            tf.load()
            synced_from = f"Local Blocklist ({tf.filepath or 'defaults'})"
        except Exception as e:
            return f"❌ SafeGuard: Failed to sync threat feed: {e}"

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
        "=" * 58,
    ])


# ==============================================================================
# Plugin Entrypoint
# ==============================================================================

def _register_tool_safely(
    ctx: Any,
    name: str,
    handler: Any,
    description: str = "",
    parameters: dict[str, Any] | None = None,
    toolset: str = "hermes-safeguard",
) -> None:
    """
    Registers a tool with Hermes PluginContext across all Hermes versions and test environments.
    Hermes Agent official API expects:
        ctx.register_tool(
            name=name,
            toolset=toolset,
            schema={
                "name": name,
                "description": description,
                "parameters": parameters,
            },
            handler=handler,
        )
    This helper prioritizes the official Hermes schema while safely falling back for test harnesses.
    """
    reg_fn = getattr(ctx, "register_tool", None)
    if not callable(reg_fn):
        return

    params_obj = parameters if parameters is not None else {"type": "object", "properties": {}}
    full_schema = {
        "name": name,
        "description": description,
        "parameters": params_obj,
    }

    import inspect
    param_names = set()
    try:
        sig = inspect.signature(reg_fn)
        param_names = set(sig.parameters.keys())
    except Exception:
        pass

    # 1. Official Hermes Agent signature: name, toolset, schema, handler
    for ts in (toolset, "safeguard", "default"):
        try:
            reg_fn(name=name, toolset=ts, schema=full_schema, handler=handler)
            return
        except TypeError:
            pass
        except Exception:
            pass

        try:
            reg_fn(name=name, toolset=ts, schema=full_schema, handler=handler, override=True)
            return
        except TypeError:
            pass
        except Exception:
            pass

    # 2. Positional Hermes Agent signature: reg_fn(name, toolset, schema, handler)
    for ts in (toolset, "safeguard", "default"):
        try:
            reg_fn(name, ts, full_schema, handler)
            return
        except TypeError:
            pass
        except Exception:
            pass

    # 3. Schema without toolset (lightweight/standalone runners)
    try:
        reg_fn(name=name, schema=full_schema, handler=handler, description=description)
        return
    except TypeError:
        pass
    except Exception:
        pass

    # 4. Legacy test harnesses with positional registration arguments
    try:
        reg_fn(name, description, params_obj, handler)
        return
    except TypeError:
        pass
    except Exception:
        pass

    # 5. Handler and name variants
    try:
        reg_fn(name=name, handler=handler, description=description)
        return
    except TypeError:
        pass
    except Exception:
        pass

    try:
        reg_fn(name, handler, description)
        return
    except TypeError:
        pass
    except Exception:
        pass

    try:
        reg_fn(name, handler)
        return
    except TypeError:
        pass
    except Exception:
        pass

    # 6. Single argument handler (decorator style)
    try:
        reg_fn(handler)
        return
    except Exception:
        pass


def register(ctx: Any) -> None:
    """
    Official Hermes Agent plugin registration entrypoint.
    Wires tools, hooks, and slash commands into the Hermes context.
    """
    # 1. Register tool: safeguard_check_policy
    check_policy_params = {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": "Destination address for the transaction (contract or EOA)",
            },
            "value": {
                "type": ["string", "integer"],
                "description": "Native asset value in wei (or ether string like '0.1 ether')",
                "default": "0",
            },
            "data": {
                "type": "string",
                "description": "Hex-encoded transaction calldata (default '0x')",
                "default": "0x",
            },
        },
        "required": ["to"],
    }
    _register_tool_safely(
        ctx=ctx,
        name="safeguard_check_policy",
        handler=safeguard_check_policy_handler,
        description="Simulate and verify an onchain transaction against SafeGuard policies without signing.",
        parameters=check_policy_params,
        toolset="hermes-safeguard",
    )

    # 2. Register tool: safeguard_execute_tx
    execute_tx_params = {
        "type": "object",
        "properties": {
            "to": {
                "type": "string",
                "description": "Destination address for the transaction (contract or EOA)",
            },
            "value": {
                "type": ["string", "integer"],
                "description": "Native asset value in wei (or ether string like '0.1 ether')",
                "default": "0",
            },
            "data": {
                "type": "string",
                "description": "Hex-encoded transaction calldata (default '0x')",
                "default": "0x",
            },
            "mode": {
                "type": "string",
                "description": "Deprecated and ignored. Policy mode is operator-controlled.",
                "enum": ["strict", "balanced", "degen"],
            },
            "gas": {
                "type": ["string", "integer"],
                "description": "Optional gas limit",
            },
            "gas_price": {
                "type": ["string", "integer"],
                "description": "Optional gas price in wei",
            },
        },
        "required": ["to"],
    }
    _register_tool_safely(
        ctx=ctx,
        name="safeguard_execute_tx",
        handler=safeguard_execute_tx_handler,
        description="Verify and execute an onchain transaction under SafeGuard policy protection.",
        parameters=execute_tx_params,
        toolset="hermes-safeguard",
    )

    # 3. Register hook: pre_tool_call
    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    # 4. Register slash commands
    # In Hermes Agent, commands are registered by base name and invoked by users in chat sessions.
    # The confirmation and rejection commands are operator-only and not callable as model tools.
    cmd_handlers = {
        # Core mode commands
        "safeguard-mode": safeguard_mode_command_handler,
        "safeguard-strict": safeguard_strict_command_handler,
        "safeguard-balanced": safeguard_balanced_command_handler,
        "safeguard-degen": safeguard_degen_command_handler,

        # Diagnostics & Status
        "safeguard-status": safeguard_status_handler,
        "safeguard-help": safeguard_help_command_handler,
        "safeguard": safeguard_help_command_handler,
        "safeguard-threats": safeguard_threats_command_handler,
        "safeguard-sync": safeguard_sync_command_handler,
        "safeguard-test-alert": safeguard_test_alert_command_handler,
        "safeguard-audit": safeguard_audit_command_handler,
        "safeguard-logs": safeguard_audit_command_handler,

        # Emergency Kill-Switch
        "safeguard-panic": safeguard_panic_command_handler,
        "safeguard-resume": safeguard_resume_command_handler,

        # Operator Confirmations
        "safeguard-pending": safeguard_pending_command_handler,
        "safeguard-confirm": safeguard_confirm_command_handler,
        "safeguard-reject": safeguard_reject_command_handler,
        "safeguard-connect-tg": safeguard_connect_tg_command_handler,
        "connect-tg": safeguard_connect_tg_command_handler,
        "connect_tg": safeguard_connect_tg_command_handler,
        "safeguard-tg": safeguard_connect_tg_command_handler,

        # Trusted Contacts & Memory Whitelist
        "safeguard-whitelist": safeguard_whitelist_command_handler,
        "safeguard-contacts": safeguard_whitelist_command_handler,
        "safeguard-allow": safeguard_allow_command_handler,
        "safeguard-whitelist-add": safeguard_allow_command_handler,
        "safeguard-revoke": safeguard_revoke_command_handler,
        "safeguard-whitelist-remove": safeguard_revoke_command_handler,
        "safeguard-check": safeguard_check_command_handler,

        # Common typo aliases (safegaurd with 'au')
        "safegaurd-mode": safeguard_mode_command_handler,
        "safegaurd-strict": safeguard_strict_command_handler,
        "safegaurd-balanced": safeguard_balanced_command_handler,
        "safegaurd-degen": safeguard_degen_command_handler,
        "safegaurd-status": safeguard_status_handler,
        "safegaurd-panic": safeguard_panic_command_handler,
        "safegaurd-resume": safeguard_resume_command_handler,
        "safegaurd-sync": safeguard_sync_command_handler,
        "safegaurd-test-alert": safeguard_test_alert_command_handler,
        "safegaurd-confirm": safeguard_confirm_command_handler,
        "safegaurd-reject": safeguard_reject_command_handler,
        "safegaurd-pending": safeguard_pending_command_handler,
        "safegaurd-help": safeguard_help_command_handler,
        "safegaurd": safeguard_help_command_handler,
    }
    cmd_descriptions = {
        "safeguard-mode": "Switch or cycle SafeGuard policy mode (strict ➔ balanced ➔ degen).",
        "safeguard-strict": "Instantly switch SafeGuard policy mode to strict.",
        "safeguard-balanced": "Instantly switch SafeGuard policy mode to balanced.",
        "safeguard-degen": "Instantly switch SafeGuard policy mode to degen.",
        "safeguard-status": "Display current SafeGuard policy mode, limits, and RPC connectivity.",
        "safeguard-help": "Display SafeGuard slash commands documentation and usage guide.",
        "safeguard": "Display SafeGuard slash commands documentation and usage guide.",
        "safeguard-threats": "View threat intelligence feeds and blocklist summary.",
        "safeguard-sync": "Force threat intelligence sync & refresh local cache.",
        "safeguard-test-alert": "Send test ping to verify Telegram/webhook alert connectivity.",
        "safeguard-panic": "Emergency kill-switch: halt all onchain financial operations.",
        "safeguard-resume": "Release emergency kill-switch & restore normal policy operations.",
        "safeguard-audit": "View recent transaction security audit decisions and history.",
        "safeguard-logs": "View recent transaction security audit decisions and history.",
        "safeguard-pending": "List all held transactions awaiting operator confirmation.",
        "safeguard-confirm": "Approve a held SafeGuard transaction by its confirmation ID.",
        "safeguard-reject": "Reject a held SafeGuard transaction by its confirmation ID.",
        "safeguard-whitelist": "List all approved/trusted addresses in SafeGuard memory.",
        "safeguard-contacts": "List all approved/trusted addresses in SafeGuard memory.",
        "safeguard-allow": "Pre-approve a trusted recipient or contract address in memory.",
        "safeguard-whitelist-add": "Pre-approve a trusted recipient or contract address in memory.",
        "safeguard-revoke": "Revoke an approved address from SafeGuard memory.",
        "safeguard-whitelist-remove": "Revoke an approved address from SafeGuard memory.",
        "safeguard-check": "Check an address reputation against threat feeds and memory.",
        "safegaurd-mode": "Switch or cycle SafeGuard policy mode (alias).",
        "safegaurd-strict": "Instantly switch SafeGuard policy mode to strict (alias).",
        "safegaurd-balanced": "Instantly switch SafeGuard policy mode to balanced (alias).",
        "safegaurd-degen": "Instantly switch SafeGuard policy mode to degen (alias).",
        "safegaurd-status": "Display current SafeGuard status (alias).",
        "safegaurd-panic": "Emergency kill-switch (alias).",
        "safegaurd-resume": "Release emergency kill-switch (alias).",
        "safegaurd-sync": "Force threat intelligence sync (alias).",
        "safegaurd-test-alert": "Test alert delivery (alias).",
        "safegaurd-confirm": "Approve a held SafeGuard transaction (alias).",
        "safegaurd-reject": "Reject a held SafeGuard transaction (alias).",
        "safegaurd-pending": "List transactions awaiting confirmation (alias).",
        "safegaurd-help": "Display SafeGuard command help (alias).",
        "safegaurd": "Display SafeGuard command help (alias).",
    }

    registered_cmds: set[str] = set()
    for reg_method_name in ("register_command", "register_slash_command"):
        reg_fn = getattr(ctx, reg_method_name, None)
        if callable(reg_fn):
            for cmd_base, handler in cmd_handlers.items():
                for cmd_name in (cmd_base, f"/{cmd_base}"):
                    if cmd_base in registered_cmds:
                        continue
                    try:
                        reg_fn(
                            name=cmd_name,
                            handler=handler,
                            description=cmd_descriptions.get(cmd_base, ""),
                        )
                        registered_cmds.add(cmd_base)
                        break
                    except TypeError:
                        try:
                            reg_fn(cmd_name, handler)
                            registered_cmds.add(cmd_base)
                            break
                        except Exception:
                            pass
                    except Exception:
                        pass

    for dict_attr in ("slash_commands", "commands"):
        d = getattr(ctx, dict_attr, None)
        if isinstance(d, dict):
            for cmd_base, handler in cmd_handlers.items():
                d[cmd_base] = handler
                d[f"/{cmd_base}"] = handler

    # 5. Register system prompt section so Hermes Agent avoids searching codebase for policy modes
    sys_prompt_fn = getattr(ctx, "register_system_prompt_section", None)
    if callable(sys_prompt_fn):
        prompt_content = (
            "Hermes SafeGuard security middleware is ACTIVE. "
            "Policy mode is operator-controlled via instant slash commands.\n"
            "When the user asks to switch policy modes, view security status, or confirm transactions, "
            "guide them to use SafeGuard slash commands instead of searching files or running scripts:\n"
            "  /safeguard-mode [strict|balanced|degen|next] - Cycle or switch policy modes instantly\n"
            "  /safeguard-strict, /safeguard-balanced, /safeguard-degen - Quick mode switches\n"
            "  /safeguard-status - View current mode, limits, and RPC connection\n"
            "  /safeguard-pending - View transactions awaiting human confirmation\n"
            "  /safeguard-confirm <id> - Approve held transaction\n"
            "  /safeguard-reject <id> - Reject held transaction\n"
            "  /safeguard-whitelist - View approved contacts/addresses\n"
            "  /safeguard-allow <addr> [label] - Pre-approve trusted address\n"
            "  /safeguard-check <addr> - Check address reputation against threat feeds\n"
            "  /safeguard-help - View complete SafeGuard command reference"
        )
        try:
            sys_prompt_fn(
                name="safeguard.guidelines",
                content=prompt_content,
                position="after_memory",
            )
        except TypeError:
            try:
                sys_prompt_fn("safeguard.guidelines", prompt_content)
            except Exception:
                pass
        except Exception:
            pass
