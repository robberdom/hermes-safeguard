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
    is_financial_tool,
    log_financial_action,
    safeguard_confirm_action,
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
        r"(?<![a-z0-9_])(?:policy_engine\.py|verifier\.py|blocklist\.json|__init__\.py|plugin\.yaml|safeguardpolicy\.sol)(?![a-z0-9_])",
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

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
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

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
        )
        risk_str = res.risk_score.value if hasattr(res.risk_score, "value") else str(res.risk_score).lower()

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
            msg = (
                f"SafeGuard [{mode.upper()}] REQUIRES OPERATOR CONFIRMATION (ID: {conf_id}):\n"
                f"{summary}\n\n"
                f"Action is held for operator approval. Operator must run /safeguard-confirm {conf_id} in chat to approve, or /safeguard-reject {conf_id} to reject."
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> REQUIRES CONFIRMATION: ID {conf_id}")
            return {
                "action": "block",
                "message": msg,
                "reason": res.reason,
                "risk_score": risk_str,
                "requires_confirmation": True,
                "confirmation_id": conf_id,
                "confirmation_summary": summary,
                "mode": mode,
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
# Slash Command: /safeguard-status
# ==============================================================================

def safeguard_status_handler(*args: Any, **kwargs: Any) -> str:
    """
    Return a summary of SafeGuard status, current policy limits, and RPC connectivity.
    Optionally switch active policy mode if a mode argument ('strict', 'balanced', 'degen')
    is supplied (e.g., /safeguard-status degen or /safeguard-mode strict).
    """
    # Check for requested mode change
    arg_text = ""
    if args:
        if isinstance(args[0], str):
            arg_text = args[0].strip().lower()
        elif isinstance(args[0], dict):
            arg_text = str(args[0].get("mode") or args[0].get("args") or "").strip().lower()
    if not arg_text and kwargs:
        arg_text = str(kwargs.get("mode") or kwargs.get("args") or kwargs.get("raw_args") or "").strip().lower()

    mode_switched = False
    tokens = [t for t in arg_text.split() if t in ("strict", "balanced", "degen")]
    if tokens:
        target_mode = tokens[-1]
        os.environ["SAFEGUARD_MODE"] = target_mode
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
        "Policy Limits:",
        f"  - Max ETH per Tx: {max_eth_display}",
        f"  - Unlimited Approvals Allowed: {unlimited_approve}",
        f"  - Zero-Slippage DEX Swaps Blocked: {zero_slippage_blocked}",
        f"  - EVM Trace Simulation Required: {simulation_required}",
        f"Anvil/RPC Connectivity: {conn_str}",
        "Toggle mode: /safeguard-mode <strict|balanced|degen>",
        "==================================================",
    ]
    return "\n".join(status_lines)


def safeguard_confirm_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to approve a held action by its confirmation_id.
    Usage: /safeguard-confirm <confirmation_id>
    """
    arg_text = ""
    if args:
        if isinstance(args[0], str):
            arg_text = args[0].strip()
        elif isinstance(args[0], dict):
            arg_text = str(args[0].get("id") or args[0].get("args") or "").strip()
    if not arg_text and kwargs:
        arg_text = str(kwargs.get("id") or kwargs.get("args") or kwargs.get("raw_args") or "").strip()

    tokens = arg_text.split()
    conf_id = tokens[0] if tokens else ""
    if not conf_id:
        return "Usage: /safeguard-confirm <confirmation_id>"

    result = safeguard_confirm_action(confirmation_id=conf_id, approved=True)
    if result.get("status") == "confirmed":
        return f"SafeGuard: Action {conf_id} has been CONFIRMED by operator."
    return f"SafeGuard: Failed to confirm {conf_id}: {result.get('message', 'Unknown error')}"


def safeguard_reject_command_handler(*args: Any, **kwargs: Any) -> str:
    """
    Operator slash command to reject a held action by its confirmation_id.
    Usage: /safeguard-reject <confirmation_id>
    """
    arg_text = ""
    if args:
        if isinstance(args[0], str):
            arg_text = args[0].strip()
        elif isinstance(args[0], dict):
            arg_text = str(args[0].get("id") or args[0].get("args") or "").strip()
    if not arg_text and kwargs:
        arg_text = str(kwargs.get("id") or kwargs.get("args") or kwargs.get("raw_args") or "").strip()

    tokens = arg_text.split()
    conf_id = tokens[0] if tokens else ""
    if not conf_id:
        return "Usage: /safeguard-reject <confirmation_id>"

    result = safeguard_confirm_action(confirmation_id=conf_id, approved=False)
    if result.get("status") == "rejected":
        return f"SafeGuard: Action {conf_id} has been REJECTED by operator."
    return f"SafeGuard: Failed to reject {conf_id}: {result.get('message', 'Unknown error')}"


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

    # 4. Register slash commands: /safeguard-status, /safeguard-mode, /safeguard-confirm, /safeguard-reject
    # In Hermes Agent, commands are registered by base name and invoked by users in chat sessions.
    # The confirmation and rejection commands are operator-only and not callable as model tools.
    cmd_handlers = {
        "safeguard-status": safeguard_status_handler,
        "safeguard-mode": safeguard_status_handler,
        "safeguard-confirm": safeguard_confirm_command_handler,
        "safeguard-reject": safeguard_reject_command_handler,
    }
    cmd_descriptions = {
        "safeguard-status": "Inspect or switch SafeGuard policy mode.",
        "safeguard-mode": "Switch SafeGuard policy mode (strict, balanced, degen).",
        "safeguard-confirm": "Approve a held SafeGuard transaction by its confirmation ID.",
        "safeguard-reject": "Reject a held SafeGuard transaction by its confirmation ID.",
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
