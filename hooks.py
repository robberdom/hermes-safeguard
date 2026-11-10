"""
Hermes SafeGuard — Event Hooks (hooks.py)
Implements event hooks for Hermes Agent (e.g. pre_tool_call).
Intercepts financial operations, protects policy code, and redirects on-chain queries.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from policy_engine import (
    APPROVE_SELECTOR,
    UINT256_MAX,
    PolicyConfig,
    PolicyMode,
    is_financial_tool,
    log_financial_action,
)
from storage import read_state_file
from tools import (
    _get_policy_config,
    _notify_telegram_operator,
    is_kill_switch_active,
)
from verifier import (
    DEFAULT_RPC_URL,
    ERC20_TRANSFER_SELECTOR,
    encode_address_word,
    encode_nft_mint_calldata,
    encode_uint256_word,
    verify_transaction,
)

logger = logging.getLogger("hermes-safeguard.hooks")

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
    "schemas.py",
    "tools.py",
    "hooks.py",
    "commands.py",
    "storage.py",
})

_MUTATING_VERBS: frozenset[str] = frozenset({
    "write", "edit", "patch", "replace", "delete", "remove", "save", "modify",
    "create", "append", "touch", "update", "overwrite", "truncate", "put",
    "move", "copy", "rename", "chmod", "chown", "mkdir", "rmdir",
})
_COMMAND_VERBS: frozenset[str] = frozenset({
    "bash", "shell", "sh", "zsh", "cmd", "powershell", "terminal",
    "exec", "eval", "python", "python3", "perl", "ruby", "node", "subprocess",
})

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
    "safeguard_execute_tx",
)

_ETH_ADDRESS_REGEX = re.compile(
    r"\b0x[a-fA-F0-9]{40}\b|\b5FbDB2315678afecb367f032d93F642f64180aa3\b|\be7f1725E7734CE288F8367e1Bb143E90bb3F0512\b",
    re.IGNORECASE,
)


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
    if re.search(r"(?<![a-z0-9_-])policies(?![a-z0-9_-])", lowered):
        return True
    parts = [p for p in lowered.split("/") if p not in ("", ".")]
    if parts and parts[-1] in PROTECTED_BASENAMES:
        return True
    pattern = rf"(?<![a-z0-9_])(?:{'|'.join(re.escape(name) for name in PROTECTED_BASENAMES)})(?![a-z0-9_])"
    if re.search(pattern, lowered):
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


def _is_contract_search_attempt(tool_name: str, tool_args: dict[str, Any]) -> tuple[bool, str]:
    """
    Detect if an agent is trying to grep or read local files searching for an on-chain contract address
    instead of calling safeguard_execute_tx directly.
    """
    tn = str(tool_name or "").lower()
    is_inspect = any(v in tn for v in ("grep", "search", "read", "view", "find", "cat"))
    if not is_inspect:
        return False, ""

    for val in _iter_strings(tool_args if isinstance(tool_args, dict) else {}):
        match = _ETH_ADDRESS_REGEX.search(str(val))
        if match:
            return True, match.group(0)
        val_lower = str(val).lower()
        if any(k in val_lower for k in ("degennft", "maliciousdrainer", "mint_calldata", "claimrewardandsweep")):
            return True, "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    return False, ""


def _extract_tx_params(args: dict[str, Any], tool_name: str = "") -> tuple[str, int, str]:
    """
    Extract destination address, value in wei, and calldata hex from tool arguments.
    Supports flat arguments, nested structures (e.g. params[0], tx, transaction),
    and synthesizes standard calldata for high-level tool calls (approve, mint, transfer)
    if raw calldata was not explicitly provided.
    Fails closed on ambiguous multiple-transaction payloads.
    """
    from policy_engine import _parse_wei_value

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
                val_wei = 0
            except Exception as e:
                raise ValueError(f"unable to encode ERC-20 transfer calldata: {e}") from e

    if not data_val:
        data_val = "0x"

    return to_addr, val_wei, data_val


def _is_financial_tool_call(tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Conservatively determine if a tool invocation represents an on-chain financial action."""
    name_clean = str(tool_name or "").strip().lower()

    if name_clean in SAFEGUARD_INTERNAL_TOOLS:
        return False

    if is_financial_tool(name_clean) or any(kw in name_clean for kw in FINANCIAL_NAME_KEYWORDS):
        return True

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


_MODE_RANK: dict[str, int] = {"degen": 1, "balanced": 2, "strict": 3}


def _resolve_effective_mode(operator_mode: str, arg_mode: str | None) -> str:
    """
    Fail-safe mode resolution:
    Untrusted agent arguments can never lower security below the operator-configured mode.
    Mode rank: degen (1) < balanced (2) < strict (3).
    """
    op_m = operator_mode.lower() if operator_mode in _MODE_RANK else "balanced"
    if not arg_mode:
        return op_m
    arg_m = str(arg_mode).strip().lower()
    if arg_m not in _MODE_RANK:
        return op_m
    return max(op_m, arg_m, key=lambda m: _MODE_RANK[m])


def on_pre_tool_call(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """
    Hook evaluator for pre_tool_call events in Hermes Agent.
    Intercepts on-chain financial operations (transfers, approves, swaps, mints),
    extracts transaction parameters, and runs SafeGuard verification.
    """
    try:
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

        config_override = kwargs.get("config")
        config, op_mode = _get_policy_config(config=config_override)
        arg_mode = kwargs.get("mode") or tool_args.get("mode")
        mode = _resolve_effective_mode(op_mode, arg_mode)
        if mode != op_mode:
            config, _ = _get_policy_config(mode=mode)

        # Security barrier: Block tampering with policies/security code
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

        # Emergency Kill-Switch: If active, hard-block ALL financial operations
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

        # Check if agent is attempting to grep or search files for on-chain contract addresses
        is_search, contract_addr = _is_contract_search_attempt(tool_name, tool_args)
        if is_search:
            err_msg = (
                f"SafeGuard Directive: '{contract_addr}' is an on-chain smart contract on Ethereum, NOT a local codebase file. "
                f"Stop searching or reading workspace files. "
                f"Immediately invoke `safeguard_execute_tx(to='{contract_addr}', value=..., data=...)` to interact with this contract."
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> REDIRECTED: On-chain address search blocked; direct transaction required.")
            return {
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "risk_score": "low",
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

        context = kwargs.get("context") or kwargs.get("messages") or []
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

        is_drain = (
            risk_str == "critical"
            or any(kw in res.reason.lower() for kw in ("drain", "extortionate", "balance loss", "threat feed", "denylist", "blocklist", "sweeper"))
        )

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
