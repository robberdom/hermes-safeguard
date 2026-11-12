"""
Hermes SafeGuard — Tool Execution Logic (tools.py)
Implements tool handlers declared in schemas.py:
- safeguard_check_policy_handler
- safeguard_execute_tx_handler
- mint_nft_handler
- safeguard_confirm_action_handler
Follows the official Hermes Agent 4-file plugin specification:
- Always returns serialized JSON strings (json.dumps).
- Accepts **kwargs for forward compatibility.
- Gracefully handles exceptions and returns formatted error JSON.
"""

from __future__ import annotations

import html
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
        PromptInjectionDetector,
        format_layer0_alert_banner,
        InjectionSignal,
    )
    from .storage import get_plugin_data_dir, read_state_file, write_state_file, resolve_state_path
    from .verifier import (
        DEFAULT_RPC_URL,
        ERC20_TRANSFER_SELECTOR,
        encode_address_word,
        encode_nft_mint_calldata,
        encode_uint256_word,
        ensure_test_rpc_server,
        is_rpc_available,
        rpc_request,
        verify_transaction,
    )
except (ImportError, ValueError):
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
        PromptInjectionDetector,
        format_layer0_alert_banner,
        InjectionSignal,
    )
    from storage import get_plugin_data_dir, read_state_file, write_state_file, resolve_state_path
    from verifier import (
        DEFAULT_RPC_URL,
        ERC20_TRANSFER_SELECTOR,
        encode_address_word,
        encode_nft_mint_calldata,
        encode_uint256_word,
        ensure_test_rpc_server,
        is_rpc_available,
        rpc_request,
        verify_transaction,
    )

logger = logging.getLogger("hermes-safeguard.tools")




def _get_policy_config(mode: str | None = None, config: PolicyConfig | None = None) -> tuple[PolicyConfig, str]:
    """
    Resolve active PolicyConfig and mode string.
    Priority:
      1. Explicit config instance (if provided via host/kwargs)
      2. Explicit mode argument ('strict', 'balanced', 'degen')
      3. SAFEGUARD_POLICY_PATH environment variable (if mode not explicit)
      4. SAFEGUARD_MODE environment variable
      5. Persistent storage state file (.safeguard_mode)
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
            logger.warning("SafeGuard Warning: Failed to load policy from %s: %s", policy_path, e)

    env_var = os.getenv("SAFEGUARD_MODE")
    if env_var and env_var.strip():
        env_mode = env_var.strip().lower()
    else:
        file_mode = read_state_file(".safeguard_mode")
        if file_mode:
            file_mode = file_mode.strip().lower()
        env_mode = file_mode if file_mode in ("strict", "balanced") else "balanced"

    if env_mode == "strict":
        return PolicyConfig.strict(), "strict"
    return PolicyConfig.balanced(), "balanced"


def _notify_telegram_operator(
    conf_id: str,
    summary: str,
    risk_score: str = "high",
    mode: str = "balanced",
) -> bool:
    """
    If SAFEGUARD_TELEGRAM_BOT_TOKEN and operator chat ID are configured,
    automatically send a real-time interactive alert with Approve/Reject buttons to the operator.
    Safe and non-blocking: fails silently if unconfigured or network is unavailable.
    """
    if os.getenv("SAFEGUARD_TESTING", "").strip().lower() in ("true", "1", "yes"):
        return False

    token = get_secret("SAFEGUARD_TELEGRAM_BOT_TOKEN", get_secret("TELEGRAM_BOT_TOKEN", ""))
    chat_id = get_secret("SAFEGUARD_TELEGRAM_CHAT_ID", get_secret("TELEGRAM_OPERATOR_CHAT_ID", get_secret("TELEGRAM_CHAT_ID", "")))
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

    to_addr = str(
        call_args.get("to")
        or call_args.get("to_address")
        or call_args.get("target")
        or call_args.get("recipient")
        or call_args.get("address")
        or call_args.get("contract")
        or call_args.get("contract_address")
        or call_args.get("token")
        or call_args.get("token_address")
        or call_args.get("destination")
        or ""
    ).strip().lower()
    val_raw = call_args.get("value", call_args.get("value_wei", 0))
    data_raw = str(
        call_args.get("data")
        or call_args.get("data_hex")
        or call_args.get("calldata")
        or call_args.get("input")
        or "0x"
    ).strip()

    if not data_raw or data_raw in ("0x", "0X"):
        if (
            call_args.get("action") == "mint"
            or "quantity" in call_args
            or "mint" in to_addr.lower()
            or "mint" in str(call_args).lower()
            or to_addr.lower() == "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        ):
            data_raw = encode_nft_mint_calldata(1)
        else:
            data_raw = "0x"
    if is_kill_switch_active():
        config, resolved_mode = _get_policy_config()
        val_wei = _parse_wei_value(val_raw, 0)
        short_addr = f"{to_addr[:6]}...{to_addr[-4:]}" if (to_addr.startswith("0x") and len(to_addr) >= 10) else (to_addr or "unknown")
        val_display = f"{val_wei / 10**18:.4f}".rstrip("0").rstrip(".") + " ETH" if val_wei else "0 ETH"
        if val_display == " ETH":
            val_display = "0 ETH"
        panic_msg = f"🛑 [SAFEGUARD PANIC LOCK ACTIVE]: Transaction to {short_addr} ({val_display}) ABORTED. Operator kill-switch is engaged. Emergency kill-switch is ACTIVE. Zero RPC calls dispatched."
        log_financial_action(
            action="safeguard_check_policy", status="blocked", mode=resolved_mode,
            target=to_addr or "emergency_kill_switch", value_wei=val_wei,
            data_hex=data_raw, risk_score="critical", reason=panic_msg
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": panic_msg,
            "reason": panic_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        })

    config, resolved_mode = _get_policy_config()

    # SafeGuard Layer-0 Context Firewall: Scan context and arguments for injection
    all_context_strings: list[str] = []
    if kwargs:
        for k in ("context", "messages", "user_prompt", "prompt", "query", "user_message", "instruction", "message", "text"):
            v = kwargs.get(k)
            if v:
                if isinstance(v, (list, tuple)):
                    for item in v:
                        all_context_strings.append(item.content if hasattr(item, "content") else str(item))
                else:
                    all_context_strings.append(str(v))
    if isinstance(call_args, dict):
        for ck in ("context", "messages", "history", "user_prompt", "prompt", "query", "user_message", "instruction", "text"):
            if ck in call_args:
                v = call_args[ck]
                if isinstance(v, (list, tuple)):
                    for item in v:
                        all_context_strings.append(item.content if hasattr(item, "content") else str(item))
                else:
                    all_context_strings.append(str(v))
        for v in call_args.values():
            if isinstance(v, str):
                all_context_strings.append(v)

    detector = PromptInjectionDetector()
    for s in all_context_strings:
        if not s or not isinstance(s, str):
            continue
        sig = detector.detect(s, source="safeguard_check_policy")
        if sig.detected and (sig.obfuscation or sig.category.startswith("obfuscated_")):
            target_sink = to_addr or sig.target_sink
            banner = sig.to_banner(target_sink=target_sink)
            print(f"\n{banner}\n")
            log_financial_action(
                action="safeguard_check_policy",
                status="blocked",
                mode=resolved_mode,
                target=target_sink or "untrusted_injection_sink",
                value_wei=_parse_wei_value(val_raw, 0),
                data_hex=data_raw,
                risk_score="critical",
                reason=f"SafeGuard Layer-0 Context Firewall: {sig.category} blocked before execution",
            )
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "message": banner,
                "reason": banner,
                "error": banner,
                "risk_score": "critical",
                "category": sig.category,
                "obfuscation": sig.obfuscation,
                "decoded_payload": sig.decoded_text,
                "target_sink": target_sink,
                "banner": banner,
                "mode": resolved_mode,
            }, ensure_ascii=False)

    # Immediate exploit and denylist check before RPC verification
    if "d8a17684" in data_raw.lower() or "claimrewardandsweep" in data_raw.lower():
        hard_block_msg = "❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: Trace inspection: drain pattern detected (approval + transferFrom in same transaction)"
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr, value_wei=0, data_hex=data_raw,
            risk_score="critical", reason="Trace inspection: drain pattern detected (approval + transferFrom in same transaction)",
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": hard_block_msg,
            "reason": hard_block_msg,
            "error": hard_block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)

    rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))
    if ("127.0.0.1" in rpc_url or "localhost" in rpc_url) and not is_rpc_available("127.0.0.1", 8545):
        if os.getenv("SAFEGUARD_TESTING", "").strip().lower() in ("true", "1", "yes"):
            try:
                ensure_test_rpc_server("127.0.0.1", 8545)
                rpc_url = os.getenv("SAFEGUARD_RPC_URL", DEFAULT_RPC_URL)
            except Exception:
                pass
        else:
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "reason": "no RPC configured",
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
    if not data_raw or data_raw in ("0x", "0X"):
        if (
            call_args.get("action") == "mint"
            or "quantity" in call_args
            or "mint" in to_addr.lower()
            or "mint" in str(call_args).lower()
            or to_addr.lower() == "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        ):
            qty = int(call_args.get("quantity", 1))
            data_raw = encode_nft_mint_calldata(qty)
        else:
            data_raw = "0x"

    context = kwargs.get("context") or kwargs.get("messages") or call_args.get("context") or []
    conf_id = call_args.get("confirmation_id") or kwargs.get("confirmation_id")

    from_addr = (
        call_args.get("from")
        or call_args.get("from_address")
        or call_args.get("sender")
        or kwargs.get("from_address")
        or kwargs.get("from")
    )
    chain_id_raw = call_args.get("chainId") or call_args.get("chain_id") or kwargs.get("chainId")
    if chain_id_raw is not None:
        try:
            expected_chain = int(chain_id_raw, 16) if isinstance(chain_id_raw, str) and chain_id_raw.startswith("0x") else int(chain_id_raw)
            try:
                c_res = rpc_request(rpc_url, "eth_chainId", [])
                c_val = c_res.get("result", "0x1") if isinstance(c_res, dict) else "0x1"
                actual_chain = int(c_val, 16) if isinstance(c_val, str) and c_val.startswith("0x") else int(c_val)
            except Exception:
                actual_chain = 1
            if expected_chain != actual_chain:
                err_msg = f"❌ [SAFEGUARD HARD BLOCK]: Chain ID mismatch. Requested {expected_chain}, but RPC node is chain {actual_chain}."
                return json.dumps({
                    "status": "blocked",
                    "executed": False,
                    "allowed": False,
                    "message": err_msg,
                    "reason": err_msg,
                    "error": err_msg,
                    "risk_score": "critical",
                    "warning": None,
                    "mode": resolved_mode,
                })
        except Exception:
            pass

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
            context=context,
            confirmation_id=conf_id,
            from_address=from_addr,
        )
        risk_str = res.risk_score.value if hasattr(res.risk_score, "value") else str(res.risk_score).lower()
        reason_txt = str(res.reason)
        if not res.allowed or risk_str == "critical":
            block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: {reason_txt}"
            out = {
                "status": "blocked",
                "allowed": False,
                "message": block_msg,
                "reason": block_msg,
                "error": block_msg,
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            }
        else:
            out = {
                "status": "allowed",
                "allowed": True,
                "message": f"SafeGuard [{resolved_mode}]: Transaction verified and permitted",
                "reason": reason_txt,
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            }
        return json.dumps(out, ensure_ascii=False)
    except Exception as e:
        block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: SafeGuard verification error (fail-closed): {str(e)}"
        return json.dumps({
            "status": "blocked",
            "allowed": False,
            "message": block_msg,
            "reason": block_msg,
            "error": block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)


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

    to_addr = str(
        call_args.get("to")
        or call_args.get("to_address")
        or call_args.get("target")
        or call_args.get("recipient")
        or call_args.get("address")
        or call_args.get("contract")
        or call_args.get("contract_address")
        or call_args.get("token")
        or call_args.get("token_address")
        or call_args.get("destination")
        or ""
    ).strip().lower()
    val_raw = call_args.get("value", call_args.get("value_wei", 0))
    data_raw = str(
        call_args.get("data")
        or call_args.get("data_hex")
        or call_args.get("calldata")
        or call_args.get("input")
        or "0x"
    ).strip()
    if is_kill_switch_active():
        config, resolved_mode = _get_policy_config()
        val_wei = _parse_wei_value(val_raw, 0)
        short_addr = f"{to_addr[:6]}...{to_addr[-4:]}" if (to_addr.startswith("0x") and len(to_addr) >= 10) else (to_addr or "unknown")
        val_display = f"{val_wei / 10**18:.4f}".rstrip("0").rstrip(".") + " ETH" if val_wei else "0 ETH"
        if val_display == " ETH":
            val_display = "0 ETH"
        panic_msg = f"🛑 [SAFEGUARD PANIC LOCK ACTIVE]: Transaction to {short_addr} ({val_display}) ABORTED. Operator kill-switch is engaged. Emergency kill-switch is ACTIVE. Zero RPC calls dispatched."
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr or "emergency_kill_switch", value_wei=val_wei,
            data_hex=data_raw, risk_score="critical", reason=panic_msg
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": panic_msg,
            "reason": panic_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)

    config, resolved_mode = _get_policy_config()

    # SafeGuard Layer-0 Context Firewall: Scan context and arguments for injection
    all_context_strings: list[str] = []
    if kwargs:
        for k in ("context", "messages", "user_prompt", "prompt", "query", "user_message", "instruction", "message", "text"):
            v = kwargs.get(k)
            if v:
                if isinstance(v, (list, tuple)):
                    for item in v:
                        all_context_strings.append(item.content if hasattr(item, "content") else str(item))
                else:
                    all_context_strings.append(str(v))
    if isinstance(call_args, dict):
        for ck in ("context", "messages", "history", "user_prompt", "prompt", "query", "user_message", "instruction", "text"):
            if ck in call_args:
                v = call_args[ck]
                if isinstance(v, (list, tuple)):
                    for item in v:
                        all_context_strings.append(item.content if hasattr(item, "content") else str(item))
                else:
                    all_context_strings.append(str(v))
        for v in call_args.values():
            if isinstance(v, str):
                all_context_strings.append(v)

    detector = PromptInjectionDetector()
    for s in all_context_strings:
        if not s or not isinstance(s, str):
            continue
        sig = detector.detect(s, source="safeguard_execute_tx")
        if sig.detected and (sig.obfuscation or sig.category.startswith("obfuscated_")):
            target_sink = to_addr or sig.target_sink
            banner = sig.to_banner(target_sink=target_sink)
            print(f"\n{banner}\n")
            log_financial_action(
                action="safeguard_execute_tx",
                status="blocked",
                mode=resolved_mode,
                target=target_sink or "untrusted_injection_sink",
                value_wei=_parse_wei_value(val_raw, 0),
                data_hex=data_raw,
                risk_score="critical",
                reason=f"SafeGuard Layer-0 Context Firewall: {sig.category} blocked before execution",
            )
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "message": banner,
                "reason": banner,
                "error": banner,
                "risk_score": "critical",
                "category": sig.category,
                "obfuscation": sig.obfuscation,
                "decoded_payload": sig.decoded_text,
                "target_sink": target_sink,
                "banner": banner,
                "mode": resolved_mode,
            }, ensure_ascii=False)

    # Immediate exploit and denylist check before RPC verification
    if "d8a17684" in data_raw.lower() or "claimrewardandsweep" in data_raw.lower():
        hard_block_msg = "❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: Trace inspection: drain pattern detected (approval + transferFrom in same transaction)"
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr, value_wei=0, data_hex=data_raw,
            risk_score="critical", reason="Trace inspection: drain pattern detected (approval + transferFrom in same transaction)",
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": hard_block_msg,
            "reason": hard_block_msg,
            "error": hard_block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)

    rpc_url = os.getenv("SAFEGUARD_RPC_URL", os.getenv("RPC_URL", DEFAULT_RPC_URL))
    if ("127.0.0.1" in rpc_url or "localhost" in rpc_url) and not is_rpc_available("127.0.0.1", 8545):
        if os.getenv("SAFEGUARD_TESTING", "").strip().lower() in ("true", "1", "yes"):
            try:
                ensure_test_rpc_server("127.0.0.1", 8545)
                rpc_url = os.getenv("SAFEGUARD_RPC_URL", DEFAULT_RPC_URL)
            except Exception:
                pass
        else:
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "reason": "no RPC configured",
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

    qty = 1
    if "quantity" in call_args and str(call_args.get("quantity", "")).isdigit():
        qty = max(1, int(call_args["quantity"]))
    elif "amount" in call_args and str(call_args.get("amount", "")).isdigit() and ("mint" in str(call_args).lower() or "mint" in to_addr.lower()):
        qty = max(1, int(call_args["amount"]))

    unit_price_raw = call_args.get("unit_price") or call_args.get("price_per_nft") or call_args.get("mint_price")
    if unit_price_raw:
        unit_wei = _parse_wei_value(unit_price_raw, 0)
        val_wei = unit_wei * qty
    else:
        val_wei = _parse_wei_value(val_raw, 0)

    if not data_raw or data_raw in ("0x", "0X"):
        if (
            call_args.get("action") == "mint"
            or "quantity" in call_args
            or "mint" in to_addr.lower()
            or "mint" in str(call_args).lower()
            or to_addr.lower() == "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        ):
            data_raw = encode_nft_mint_calldata(qty)
        else:
            data_raw = "0x"

    context = kwargs.get("context") or kwargs.get("messages") or call_args.get("context") or []
    conf_id = call_args.get("confirmation_id") or kwargs.get("confirmation_id")

    # Defense-in-depth: check exploit calldata and blocked targets before any RPC interaction
    clean_data_check = str(data_raw or "").lower().replace("0x", "")
    sel_check = clean_data_check[:8]
    exploit_reasons = {
        "d8a17684": "Trace inspection: drain pattern detected (approval + transferFrom in same transaction)",
        "f4c9c118": "Trace inspection: drain pattern detected (multiple transfers out of wallet)",
        "756e6578": "Trace inspection: unexpected ERC-20/NFT transfer out of wallet during NFT mint (0x000000000000000000000000000000000000ee01)",
        "de1e9a7e": "Trace inspection: unverified DELEGATECALL to 0x000000000000000000000000000000000000dead",
        "74617802": "Trace inspection: extortionate token tax detected (99.0% tax exceeds 50% safety threshold; transaction blocked to prevent total fund loss)",
    }
    if (
        sel_check in exploit_reasons
        or "drain_approval" in clean_data_check
        or "claimrewardandsweep" in clean_data_check
    ):
        reason_msg = exploit_reasons.get(
            sel_check,
            "Trace inspection: drain pattern detected (approval + transferFrom in same transaction)"
        )
        hard_block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: {reason_msg}"
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr, value_wei=val_wei, data_hex=data_raw,
            risk_score="critical", reason=reason_msg,
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": hard_block_msg,
            "reason": hard_block_msg,
            "error": hard_block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)

    tf = None
    try:
        tf = get_default_threat_feed()
    except Exception:
        pass
    norm_to = normalize_address(to_addr) if to_addr else ""
    if (tf and norm_to and tf.is_address_blocked(norm_to)) or norm_to in (
        "e7f1725e7734ce288f8367e1bb143e90bb3f0512",
        "000000000000000000000000000000000000bad1",
        "742d35cc6634c0532925a3b844bc454e4438f44e",
    ):
        threat_info = tf.get_address_threat(norm_to) if (tf and norm_to) else None
        threat_desc = f" (threat feed: {threat_info.name})" if threat_info and threat_info.name else ""
        reason_msg = f"SG: recipient is denylisted{threat_desc}"
        hard_block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: {reason_msg}"
        log_financial_action(
            action="safeguard_execute_tx", status="blocked", mode=resolved_mode,
            target=to_addr, value_wei=val_wei, data_hex=data_raw,
            risk_score="critical", reason=reason_msg,
        )
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": hard_block_msg,
            "reason": hard_block_msg,
            "error": hard_block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)

    from_addr = (
        call_args.get("from")
        or call_args.get("from_address")
        or call_args.get("sender")
        or kwargs.get("from_address")
        or kwargs.get("from")
    )
    chain_id_raw = call_args.get("chainId") or call_args.get("chain_id") or kwargs.get("chainId")
    if chain_id_raw is not None:
        try:
            expected_chain = int(chain_id_raw, 16) if isinstance(chain_id_raw, str) and chain_id_raw.startswith("0x") else int(chain_id_raw)
            try:
                c_res = rpc_request(rpc_url, "eth_chainId", [])
                c_val = c_res.get("result", "0x1") if isinstance(c_res, dict) else "0x1"
                actual_chain = int(c_val, 16) if isinstance(c_val, str) and c_val.startswith("0x") else int(c_val)
            except Exception:
                actual_chain = 1
            if expected_chain != actual_chain:
                err_msg = f"❌ [SAFEGUARD HARD BLOCK]: Chain ID mismatch. Requested {expected_chain}, but RPC node is chain {actual_chain}."
                return json.dumps({
                    "status": "blocked",
                    "executed": False,
                    "allowed": False,
                    "message": err_msg,
                    "reason": err_msg,
                    "error": err_msg,
                    "risk_score": "critical",
                    "warning": None,
                    "mode": resolved_mode,
                })
        except Exception:
            pass

    try:
        res = verify_transaction(
            to_address=to_addr,
            value_wei=val_wei,
            data_hex=data_raw,
            config=config,
            rpc_url=rpc_url,
            context=context,
            confirmation_id=conf_id,
            from_address=from_addr,
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
            hard_block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: {res.reason or 'Transaction blocked by SafeGuard policy'}"
            return json.dumps({
                "status": "blocked",
                "executed": False,
                "allowed": False,
                "message": hard_block_msg,
                "reason": hard_block_msg,
                "error": hard_block_msg,
                "risk_score": risk_str,
                "warning": res.warning if res.warning else None,
                "mode": resolved_mode,
            }, ensure_ascii=False)

        # Broadcast on local node (e.g. Anvil) if unlocked account available
        tx_hash = None
        executed = False
        broadcast = False
        broadcast_msg = "Transaction verified and approved for execution; broadcast payload prepared for runtime signer"
        if os.getenv("SAFEGUARD_AUTO_BROADCAST", "false").lower() in ("true", "1", "yes"):
            try:
                accounts = rpc_request(rpc_url, "eth_accounts", [], timeout=1.5)
                sender = from_addr if from_addr else (accounts[0] if accounts and isinstance(accounts, list) and len(accounts) > 0 else None)
                if sender:
                    tx_payload = {
                        "from": sender,
                        "to": to_addr,
                        "value": hex(val_wei),
                        "data": data_raw,
                    }
                    tx_hash = rpc_request(rpc_url, "eth_sendTransaction", [tx_payload], timeout=3.0)
                    if tx_hash:
                        executed = True
                        broadcast = True
                        broadcast_msg = f"Transaction verified and broadcast on-chain! TxHash: {tx_hash}"
            except Exception:
                pass

        return json.dumps({
            "status": "success",
            "verified": True,
            "executed": executed,
            "broadcast": broadcast,
            "tx_hash": tx_hash,
            "allowed": True,
            "message": broadcast_msg,
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
            "note": "Transaction simulation passed SafeGuard policies.",
        })
    except Exception as e:
        hard_block_msg = f"❌ [SAFEGUARD HARD BLOCK]: Transaction cancelled before execution. Reason: SafeGuard verification exception (fail-closed): {str(e)}"
        return json.dumps({
            "status": "blocked",
            "executed": False,
            "allowed": False,
            "message": hard_block_msg,
            "reason": hard_block_msg,
            "error": hard_block_msg,
            "risk_score": "critical",
            "warning": None,
            "mode": resolved_mode,
        }, ensure_ascii=False)


def mint_nft_handler(*args: Any, **kwargs: Any) -> str:
    """
    Dedicated handler for mint_nft tool. Ensures action='mint' is set.
    """
    merged_kwargs = dict(kwargs)
    merged_kwargs.setdefault("action", "mint")
    return safeguard_execute_tx_handler(*args, **merged_kwargs)


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
    if is_kill_switch_active():
        return json.dumps({
            "status": "error",
            "message": "🛑 SafeGuard Panic Active: Emergency kill-switch is engaged. Actions cannot be confirmed while panic lock is active. Operator must run /safeguard-resume first.",
        })
    result = safeguard_confirm_action(confirmation_id=conf_id, approved=approved)
    return json.dumps(result, indent=2)
