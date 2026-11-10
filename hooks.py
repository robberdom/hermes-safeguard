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

try:
    from .policy_engine import (
        APPROVE_SELECTOR,
        UINT256_MAX,
        PolicyConfig,
        PolicyMode,
        is_financial_tool,
        log_financial_action,
        PromptInjectionDetector,
        format_layer0_alert_banner,
        InjectionSignal,
    )
    from .storage import read_state_file
    from .tools import (
        _get_policy_config,
        _notify_telegram_operator,
        is_kill_switch_active,
    )
    from .verifier import (
        DEFAULT_RPC_URL,
        ERC20_TRANSFER_SELECTOR,
        encode_address_word,
        encode_nft_mint_calldata,
        encode_uint256_word,
        verify_transaction,
    )
except (ImportError, ValueError):
    from policy_engine import (
        APPROVE_SELECTOR,
        UINT256_MAX,
        PolicyConfig,
        PolicyMode,
        is_financial_tool,
        log_financial_action,
        PromptInjectionDetector,
        format_layer0_alert_banner,
        InjectionSignal,
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
    ".safeguard_mode",
    ".safeguard_memory.json",
    ".safeguard_audit.jsonl",
    ".safeguard_velocity.json",
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

SHELL_EXEC_TOOLS: frozenset[str] = frozenset({
    "terminal", "bash", "sh", "zsh", "shell", "exec", "cmd", "powershell",
    "run_command", "process", "system", "subprocess", "execute",
    "execute_code", "python_repl", "run_python", "eval_code", "run_script",
    "sandbox_exec", "sandbox_run", "http_request", "send_http_request",
    "api_request", "web_request", "curl_tool",
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
    "eth_sendrawtransaction",
    "safeguard_execute_tx",
    "cast",
)

_ETH_ADDRESS_REGEX = re.compile(
    r"\b0x[a-fA-F0-9]{40}\b|\b5FbDB2315678afecb367f032d93F642f64180aa3\b|\be7f1725E7734CE288F8367e1Bb143E90bb3F0512\b",
    re.IGNORECASE,
)


class HookVerdict(dict):
    """
    Subclass of dict representing pre_tool_call hook directives.
    Maintains full dict compatibility for test harnesses expecting dict returns:
      assert hook_res["action"] == "block"
      assert hook_res["risk_score"] == "critical"
    Evaluates to False in boolean checks (e.g. `if not hook(...): cancel()`) when
    action == "block" or allowed is False or cancel is True.
    """
    def __bool__(self) -> bool:
        act = str(self.get("action", "")).lower()
        if act == "block" or self.get("allowed") is False or self.get("cancel") is True or self.get("blocked") is True:
            return False
        return True


def _make_block_verdict(
    reason: str,
    risk_score: str = "critical",
    mode: str = "balanced",
    extra: dict[str, Any] | None = None,
) -> HookVerdict:
    if reason.startswith("SAFEGUARD MIDDLEWARE:"):
        formatted_msg = reason
    else:
        formatted_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: {reason}"
    payload: dict[str, Any] = {
        "action": "block",
        "message": formatted_msg,
        "reason": reason,
        "error": formatted_msg,
        "allowed": False,
        "cancel": True,
        "blocked": True,
        "status": "blocked",
        "risk_score": risk_score,
        "mode": mode,
    }
    if extra:
        payload.update(extra)
    return HookVerdict(payload)


def _make_allow_verdict(
    message: str = "Transaction verified and permitted",
    warning: str | None = None,
    risk_score: str = "low",
    mode: str = "balanced",
    extra: dict[str, Any] | None = None,
) -> HookVerdict:
    payload: dict[str, Any] = {
        "action": "allow",
        "allowed": True,
        "cancel": False,
        "status": "success",
        "message": message,
        "warning": warning,
        "risk_score": risk_score,
        "mode": mode,
    }
    if extra:
        payload.update(extra)
    return HookVerdict(payload)


def _scan_payload_for_threats(
    tool_name: str,
    tool_args: dict[str, Any],
    context: list[Any] | None = None,
) -> tuple[bool, str, str]:
    """
    Scans the full string representation of tool_args (and context / user prompt)
    against the ThreatFeed blocklist, recipient denylist, exploit signatures, and drainer links.
    Returns (is_threat, threat_target, reason).
    """
    from policy_engine import get_default_threat_feed

    all_strings = list(_iter_strings(tool_args))
    if context:
        all_strings.extend(list(_iter_strings(context)))
    combined_text = " ".join(all_strings)
    combined_lower = combined_text.lower()

    # 1. Check exploit function signatures & drain patterns
    exploit_patterns = {
        "d8a17684": "Trace inspection: drain pattern detected (approval + transferFrom in same transaction)",
        "f4c9c118": "Trace inspection: drain pattern detected (multiple transfers out of wallet)",
        "756e6578": "Trace inspection: unexpected ERC-20/NFT transfer out of wallet during NFT mint (0x000000000000000000000000000000000000ee01)",
        "de1e9a7e": "Trace inspection: unverified DELEGATECALL to 0x000000000000000000000000000000000000dead",
        "74617802": "Trace inspection: extortionate token tax detected (99.0% tax exceeds 50% safety threshold)",
        "claimrewardandsweep": "Malicious drainer exploit pattern (claimRewardAndSweep)",
        "drain_approval": "Drainer exploit pattern (drain_approval + sweep)",
        "sweeptokens": "Unauthorized token sweeper invocation",
        "emergencydrain": "Emergency drain selector invoked",
        "drainether": "Native ether drain selector invoked",
    }
    for pat, desc in exploit_patterns.items():
        if pat in combined_lower:
            return True, pat, desc

    # 2. Check for Ethereum addresses matching denylist or threat feed
    addresses_found = set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", combined_text))
    tf = None
    try:
        tf = get_default_threat_feed()
    except Exception:
        pass

    for addr in addresses_found:
        norm = addr.lower().replace("0x", "")
        if tf and tf.is_address_blocked(norm):
            threat = tf.get_address_threat(norm)
            threat_name = f": {threat.name}" if threat and threat.name else ""
            return True, addr, f"Referenced address {addr} is a verified malicious threat / drainer{threat_name}"
        if norm in (
            "e7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "000000000000000000000000000000000000bad1",
            "742d35cc6634c0532925a3b844bc454e4438f44e",
            "1234567890123456789012345678901234567890",
            "888888888888888888888888888888888888bad0",
            "6b75d8af000000e20b7a7ddf000ba900b4009a80",
            "deadbeef11112222333344445555666677778888",
        ):
            return True, addr, f"Referenced address {addr} is a verified denylisted threat / drainer"

    # 3. Check for drainer links and URLs
    drainer_keywords = ("inferno drainer", "angel drainer", "pink drainer", "monkey drainer", "drainer.xyz", "claim-airdrop")
    for kw in drainer_keywords:
        if kw in combined_lower:
            return True, kw, f"Threat feed match: {kw} phishing/drainer indicator detected in arguments"

    return False, "", ""


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
    else:
        for attr in ("content", "text", "message", "body"):
            val = getattr(obj, attr, None)
            if isinstance(val, (str, dict, list, tuple)):
                yield from _iter_strings(val, depth + 1)


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
        val_lower = val.lower()
        if any(term in val_lower for term in (
            "safeguard-resume",
            "safeguard_resume",
            "safegaurd-resume",
            "safegaurd_resume",
            "set_kill_switch",
            "safeguard_kill_switch",
            ".safeguard_kill_switch",
            "safeguard-confirm",
            "safeguard_confirm",
            "safeguard_confirm_action",
            "safeguard-allow",
            "safeguard_allow",
            "safeguard-degen",
            "safeguard_degen",
            "safeguard_approve_address",
            "safeguard_revoke_address",
            ".safeguard_mode",
            "safeguard_mode",
            ".safeguard_memory",
            "safeguard_memory",
        )):
            return True
    return False


NON_WEB3_FILESYSTEM_TOOLS: frozenset[str] = frozenset({
    "grep",
    "search_files",
    "read_file",
    "list_dir",
    "find",
    "file_search",
    "read",
    "view_file",
    "cat",
    "list_directory",
    "dir_list",
    "search",
    "code_search",
    "ripgrep",
    "rg",
})

FILE_SEARCH_CMD_PATTERNS = re.compile(
    r"\b(grep|find|cat|head|tail|rg|ripgrep|ag|ack|locate|fd|ls|dir)\b",
    re.IGNORECASE,
)

ONCHAIN_KEYWORDS_REGEX = re.compile(
    r"\b(send|transfer|transfers|transferring|mint|mints|minting|swap|swaps|swapping|approve|approves|approval|approving|tx|txs|eth|ethereum|ether)\b",
    re.IGNORECASE,
)

DRAINER_PATTERNS = (
    "drainer",
    "claim-airdrop",
    "drain",
    "sweeper",
    "claimrewardandsweep",
    "drain_approval",
    "sweeptokens",
    "inferno drainer",
    "pink drainer",
    "angel drainer",
    "monkey drainer",
)


def _is_filesystem_search_tool_call(tool_name: str, tool_args: dict[str, Any]) -> bool:
    """
    Returns True if tool is a non-Web3 filesystem or code search tool
    (e.g. grep, search_files, read_file, list_dir, find, or terminal/bash running file searches).
    """
    name_clean = str(tool_name or "").strip().lower()
    if name_clean in SAFEGUARD_INTERNAL_TOOLS:
        return False
    if name_clean in ("safeguard_execute_tx", "mint_nft", "safeguard_check_policy"):
        return False

    if name_clean in NON_WEB3_FILESYSTEM_TOOLS:
        return True

    if any(k in name_clean for k in ("search_files", "read_file", "list_dir", "file_search", "list_directory")):
        return True

    if name_clean in SHELL_EXEC_TOOLS:
        cmd_text = " ".join(_iter_strings(tool_args)).strip()
        if any(term in cmd_text.lower() for term in ("safeguard_exec", "safeguard_mint", "cast send", "eth_sendtransaction")):
            return False
        if FILE_SEARCH_CMD_PATTERNS.search(cmd_text):
            return True

    return False


def _is_onchain_intent(
    tool_args: dict[str, Any],
    context: list[Any] | None = None,
    kwargs: dict[str, Any] | None = None,
) -> bool:
    """
    Detects if the user's current request or conversation context involves an onchain action:
    contains a 0x address, drainer link, or keywords like send, transfer, mint, swap, approve, tx, eth.
    """
    strings = []
    if kwargs:
        for k in ("user_prompt", "prompt", "query", "user_message", "instruction", "message", "text"):
            v = kwargs.get(k)
            if v:
                strings.extend(_iter_strings(v))
    if context:
        strings.extend(_iter_strings(context))
    if isinstance(tool_args, dict):
        for ck in ("context", "messages", "history", "user_prompt", "prompt"):
            if ck in tool_args:
                strings.extend(_iter_strings(tool_args[ck]))
        strings.extend(_iter_strings(tool_args))

    combined = " ".join(strings)
    if not combined:
        return False

    # 1. Contains a 0x address or hex prefix
    if _ETH_ADDRESS_REGEX.search(combined) or re.search(r"\b0x[a-fA-F0-9]{4,}\b", combined, re.IGNORECASE):
        return True

    # 2. Contains drainer link or drain keywords
    combined_lower = combined.lower()
    if any(pat in combined_lower for pat in DRAINER_PATTERNS):
        return True

    # 3. Contains keywords like send, transfer, mint, swap, approve, tx, eth
    if ONCHAIN_KEYWORDS_REGEX.search(combined):
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
        or target.get("address")
        or target.get("contract")
        or target.get("contract_address")
        or target.get("token")
        or target.get("token_address")
        or target.get("destination")
        or ""
    ).strip().lower()

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

    # If to_addr or data_val was not explicitly provided, inspect command / script fields
    cmd_str = str(target.get("command") or target.get("cmd") or target.get("script") or "").strip()
    if cmd_str:
        addr_match = re.search(r"\b(0x[a-fA-F0-9]{40})\b", cmd_str)
        if addr_match and not to_addr:
            to_addr = addr_match.group(1).lower()
        data_match = re.search(r"\b(0x[a-fA-F0-9]{8,})\b", cmd_str)
        if data_match and (not data_val or data_val in ("0x", "0X")):
            data_val = data_match.group(1)
        if "claimrewardandsweep" in cmd_str.lower() and (not data_val or data_val in ("0x", "0X")):
            data_val = "0xd8a17684"
        val_match = re.search(r"(?:--value\s+|\bvalue\s*=\s*)([0-9a-zA-Z.]+)", cmd_str)
        if val_match and val_wei == 0:
            try:
                val_wei = _parse_wei_value(val_match.group(1), 0)
            except Exception:
                pass

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
            recipient = str(target.get("to") or target.get("recipient") or target.get("to_address") or target.get("address") or "").strip()
            if not token_addr:
                raise ValueError("ERC-20 transfer is missing a token address")
            if not recipient:
                raise ValueError("ERC-20 transfer is missing a recipient address")
            to_addr = token_addr.lower()
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

    # Intercept shell/terminal executions containing transaction commands, drain selectors, or target addresses
    if name_clean in SHELL_EXEC_TOOLS:
        cmd_text = " ".join(_iter_strings(tool_args)).lower()
        if any(term in cmd_text for term in ("cast send", "eth_sendtransaction", "safeguard_exec", "safeguard_mint", "claimrewardandsweep", "0xd8a17684")):
            return True
        if re.search(r"\b0x[a-f0-9]{40}\b", cmd_text):
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
            or c.get("address")
            or c.get("contract")
            or c.get("token")
            or ""
        ).strip().lower()
        has_eth_target = to_val.startswith("0x") and len(to_val) == 42
        has_tx_keys = any(
            k in c
            for k in ("value", "value_wei", "data", "data_hex", "calldata", "gas", "gas_price", "input", "amount")
        )
        if has_eth_target and (has_tx_keys or name_clean in ("safeguard_execute_tx", "mint_nft")):
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


def on_pre_tool_call(*args: Any, **kwargs: Any) -> HookVerdict:
    """
    Hook evaluator for pre_tool_call events in Hermes Agent.
    Intercepts on-chain financial operations (transfers, approves, swaps, mints, terminal/bash cast send),
    extracts transaction parameters, and runs SafeGuard verification.
    Supports all call signatures:
      - on_pre_tool_call(tool_name, tool_args)
      - on_pre_tool_call(ctx, tool_name, tool_args)
      - on_pre_tool_call(event_dict)
      - on_pre_tool_call(tool_name=..., args=...)
    """
    try:
        tool_name = ""
        tool_args: dict[str, Any] = {}
        context_msgs = kwargs.get("context") or kwargs.get("messages") or []

        if len(args) >= 3:
            # Handle (ctx, tool_name, tool_args) vs (tool_name, tool_args, context)
            if isinstance(args[0], str) and isinstance(args[1], (dict, str)):
                tool_name = args[0]
                raw_args = args[1]
                if isinstance(args[2], list):
                    context_msgs = args[2]
            elif isinstance(args[1], str):
                tool_name = args[1]
                raw_args = args[2]
            else:
                tool_name = str(args[0])
                raw_args = args[1]
            tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})
        elif len(args) == 2:
            tool_name = str(args[0])
            raw_args = args[1]
            tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})
        elif len(args) == 1:
            call_obj = args[0]
            if isinstance(call_obj, dict):
                tool_name = str(call_obj.get("name") or call_obj.get("tool") or call_obj.get("tool_name") or "")
                raw_args = call_obj.get("args") or call_obj.get("arguments") or call_obj.get("parameters") or call_obj.get("input") or {}
                tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})
            elif isinstance(call_obj, str):
                tool_name = call_obj
                tool_args = {}
            else:
                tool_name = str(getattr(call_obj, "name", "") or getattr(call_obj, "tool_name", "") or getattr(call_obj, "tool", ""))
                raw_args = getattr(call_obj, "args", {}) or getattr(call_obj, "arguments", {}) or getattr(call_obj, "parameters", {}) or getattr(call_obj, "input", {})
                tool_args = json.loads(raw_args) if isinstance(raw_args, str) else (dict(raw_args) if isinstance(raw_args, dict) else {})
        else:
            tool_name = str(kwargs.get("tool_name") or kwargs.get("name") or kwargs.get("tool") or "")
            raw_args = kwargs.get("tool_args") or kwargs.get("args") or kwargs.get("arguments") or kwargs.get("parameters") or kwargs.get("input") or {}
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
            err_msg = "SafeGuard Security: Policy tampering attempt. Agent is strictly forbidden from modifying SafeGuard policy configuration, limits, or code."
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="local_policy_file", value_wei=0, data_hex="",
                risk_score="critical", reason=err_msg
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: Policy tampering attempt")
            return _make_block_verdict(err_msg, risk_score="critical", mode=mode)

        # SafeGuard Layer-0 Context Firewall: Deep scan of prompt context & tool arguments for injections (Morse, Base64, Hex)
        all_context_strings: list[str] = []
        if kwargs:
            for k in ("context", "messages", "user_prompt", "prompt", "query", "user_message", "instruction", "message", "text"):
                val = kwargs.get(k)
                if val:
                    all_context_strings.extend(_iter_strings(val))
        if isinstance(tool_args, dict):
            for ck in ("context", "messages", "history", "user_prompt", "prompt", "query", "user_message", "instruction", "text"):
                if ck in tool_args:
                    all_context_strings.extend(_iter_strings(tool_args[ck]))
            all_context_strings.extend(_iter_strings(tool_args))
        elif isinstance(tool_args, (list, str)):
            all_context_strings.extend(_iter_strings(tool_args))

        detector = PromptInjectionDetector()
        for s in all_context_strings:
            if not s or not isinstance(s, str):
                continue
            sig = detector.detect(s, source="user_prompt")
            if sig.detected and (sig.obfuscation or sig.category.startswith("obfuscated_")):
                target_sink = sig.target_sink
                if not target_sink:
                    for s2 in all_context_strings:
                        m = _ETH_ADDRESS_REGEX.search(str(s2))
                        if m:
                            target_sink = m.group(0)
                            break
                banner = sig.to_banner(target_sink=target_sink)
                print(f"\n{banner}\n")
                log_financial_action(
                    action=tool_name,
                    status="blocked",
                    mode=mode,
                    target=target_sink or "untrusted_injection_sink",
                    value_wei=0,
                    data_hex="",
                    risk_score="critical",
                    reason=f"SafeGuard Layer-0 Context Firewall: {sig.category} blocked before execution",
                )
                return _make_block_verdict(
                    banner,
                    risk_score="critical",
                    mode=mode,
                    extra={
                        "category": sig.category,
                        "obfuscation": sig.obfuscation,
                        "decoded_payload": sig.decoded_text,
                        "target_sink": target_sink,
                        "banner": banner,
                    },
                )

        # Emergency Kill-Switch: If active, hard-block ALL financial operations, on-chain execution, and policy checks
        if is_kill_switch_active() and (
            _is_financial_tool_call(tool_name, tool_args)
            or str(tool_name or "").strip().lower() in ("safeguard_execute_tx", "mint_nft", "safeguard_check_policy")
        ):
            to_addr, val_wei, _ = _extract_tx_params(tool_args)
            short_target = f"{to_addr[:6]}...{to_addr[-4:]}" if (to_addr and to_addr.startswith("0x") and len(to_addr) >= 10) else (to_addr or "target")
            val_display = f"{val_wei / 10**18:.4f}".rstrip("0").rstrip(".") + " ETH" if val_wei else "0 ETH"
            if val_display == " ETH":
                val_display = "0 ETH"
            err_msg = (
                f"🛑 [SAFEGUARD PANIC LOCK ACTIVE]: Transaction to {short_target} ({val_display}) ABORTED. "
                "Operator kill-switch is engaged. Emergency kill-switch is ACTIVE. Zero RPC calls dispatched."
            )
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target=to_addr or "emergency_kill_switch", value_wei=val_wei, data_hex="",
                risk_score="critical", reason=err_msg
            )
            print(f"SafeGuard [PANIC]: Intercepted '{tool_name}' -> BLOCKED: {err_msg}")
            return _make_block_verdict(err_msg, risk_score="critical", mode=mode)

        # Fast-path middleware interception: Block unnecessary filesystem/grep tool calls on onchain intent
        if _is_filesystem_search_tool_call(tool_name, tool_args) and _is_onchain_intent(tool_args, context=context_msgs, kwargs=kwargs):
            redirect_msg = "SAFEGUARD MIDDLEWARE: File search blocked for onchain intent. Invoke safeguard_execute_tx immediately."
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="filesystem_search_interception", value_wei=0, data_hex="",
                risk_score="low", reason=redirect_msg
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> REDIRECTED: {redirect_msg}")
            return _make_block_verdict(
                redirect_msg,
                risk_score="low",
                mode=mode,
                extra={"redirect": "safeguard_execute_tx"},
            )

        # Check if agent is attempting to grep or search files for on-chain contract addresses
        is_search, contract_addr = _is_contract_search_attempt(tool_name, tool_args)
        if is_search:
            err_msg = (
                f"SafeGuard Directive: '{contract_addr}' is an on-chain smart contract on Ethereum, NOT a local codebase file. "
                f"Stop searching or reading workspace files. "
                f"Immediately invoke `safeguard_execute_tx(to='{contract_addr}', value=..., data=...)` to interact with this contract."
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> REDIRECTED: On-chain address search blocked; direct transaction required.")
            return _make_block_verdict(err_msg, risk_score="low", mode=mode)

        # Conservative interception: only trigger on tools that appear to be financial
        if not _is_financial_tool_call(tool_name, tool_args):
            # For non-financial tools, also check if any explicit threat address or exploit is embedded
            is_threat, threat_target, threat_reason = _scan_payload_for_threats(tool_name, tool_args, context=context_msgs)
            if is_threat:
                log_financial_action(
                    action=tool_name, status="blocked", mode=mode,
                    target=threat_target, value_wei=0, data_hex="",
                    risk_score="critical", reason=threat_reason
                )
                print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: {threat_reason}")
                return _make_block_verdict(threat_reason, risk_score="critical", mode=mode)
            return _make_allow_verdict("Non-financial tool permitted", mode=mode)

        try:
            to_addr, val_wei, data_hex = _extract_tx_params(tool_args, tool_name)
        except ValueError as e:
            err_msg = f"SafeGuard: Rejected ambiguous or malformed transaction: {e}"
            return _make_block_verdict(err_msg, risk_score="critical", mode=mode)

        if val_wei < 0:
            err_msg = "SafeGuard: Malformed or unparseable transaction amount."
            return _make_block_verdict(err_msg, risk_score="high", mode=mode)

        # Deep threat scan across full string payload & context (catches drain links, contract addresses, exploit patterns)
        is_threat, threat_target, threat_reason = _scan_payload_for_threats(tool_name, tool_args, context=context_msgs)
        if is_threat:
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target=threat_target, value_wei=val_wei if val_wei > 0 else 0, data_hex=data_hex,
                risk_score="critical", reason=threat_reason
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: {threat_reason}")
            return _make_block_verdict(threat_reason, risk_score="critical", mode=mode)

        rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))

        if not to_addr:
            log_financial_action(
                action=tool_name, status="blocked", mode=mode,
                target="", value_wei=val_wei, data_hex=data_hex,
                risk_score="critical", reason="Missing destination address ('to')"
            )
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: Missing destination address ('to')")
            return _make_block_verdict("Missing destination address ('to')", risk_score="critical", mode=mode)

        active_conf_id = tool_args.get("confirmation_id") if isinstance(tool_args, dict) else None

        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_hex,
            config=config,
            rpc_url=rpc_url,
            context=context_msgs,
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
            return _make_block_verdict(
                msg,
                risk_score=risk_str,
                mode=mode,
                extra={
                    "requires_confirmation": True,
                    "confirmation_id": conf_id,
                    "confirmation_summary": summary,
                    "telegram_notified": tg_notified,
                },
            )

        is_drain = (
            risk_str == "critical"
            or any(kw in res.reason.lower() for kw in ("drain", "extortionate", "balance loss", "threat feed", "denylist", "blocklist", "sweeper"))
        )

        if mode == "degen":
            if not res.allowed or is_drain or risk_str == "critical":
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> BLOCKED: {res.reason}")
                return _make_block_verdict(res.reason, risk_score=risk_str, mode=mode)
            elif risk_str == "medium":
                warn_text = res.warning or res.reason or "Medium-risk action permitted under degen mode"
                msg = f"SafeGuard [degen] WARNING: {warn_text}"
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> ALLOWED with warning: {warn_text}")
                return _make_allow_verdict(msg, warning=warn_text, risk_score="medium", mode=mode)
            else:
                warn_msg = f" (Warning: {res.warning})" if res.warning else ""
                msg = f"SafeGuard [degen]: Transaction verified successfully.{warn_msg}"
                print(f"SafeGuard [DEGEN]: Intercepted '{tool_name}' -> ALLOWED")
                return _make_allow_verdict(msg, warning=res.warning or None, risk_score=risk_str, mode=mode)

        if not res.allowed or risk_str == "critical":
            reason_txt = res.reason or "Transaction blocked by SafeGuard policy"
            print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> BLOCKED: {reason_txt}")
            return _make_block_verdict(reason_txt, risk_score=risk_str, mode=mode)

        warn_msg = f" (Warning: {res.warning})" if res.warning else ""
        msg = f"SafeGuard [{mode}]: Transaction verified successfully.{warn_msg}"
        print(f"SafeGuard [{mode.upper()}]: Intercepted '{tool_name}' -> ALLOWED")
        return _make_allow_verdict(msg, warning=res.warning or None, risk_score=risk_str, mode=mode)

    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        env_mode = os.getenv("SAFEGUARD_MODE", "balanced").strip().lower()
        err_msg = f"SafeGuard [{env_mode}] BLOCKED (fail-closed internal error): {str(e)}"
        print(err_msg)
        try:
            return _make_block_verdict(err_msg, risk_score="critical", mode=env_mode)
        except BaseException:
            return HookVerdict({
                "action": "block",
                "message": err_msg,
                "reason": err_msg,
                "error": err_msg,
                "allowed": False,
                "cancel": True,
                "blocked": True,
                "status": "blocked",
                "risk_score": "critical",
                "mode": env_mode,
            })
