"""
Hermes SafeGuard — Registration & Plugin Entrypoint (__init__.py)
Wires schemas to handlers, registers event hooks and slash commands.
Compliant with Hermes Agent Plugin Developer Guide:
- plugin.yaml: declares capabilities
- schemas.py: tool schemas for LLM consumption
- tools.py: tool execution logic
- __init__.py: registration entrypoint via register(ctx)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

# Schemas, Tools, Hooks, Commands & Helpers
try:
    from .schemas import (
        ALL_TOOL_SCHEMAS,
        MINT_NFT_SCHEMA,
        SAFEGUARD_CHECK_POLICY_SCHEMA,
        SAFEGUARD_EXECUTE_TX_SCHEMA,
    )
    from .tools import (
        _get_policy_config,
        _notify_telegram_operator,
        is_kill_switch_active,
        mint_nft_handler,
        safeguard_check_policy_handler,
        safeguard_confirm_action_handler,
        safeguard_execute_tx_handler,
        set_kill_switch,
    )
    from .hooks import (
        FINANCIAL_NAME_KEYWORDS,
        PROTECTED_BASENAMES,
        SAFEGUARD_INTERNAL_TOOLS,
        _COMMAND_VERBS,
        _ETH_ADDRESS_REGEX,
        _MUTATING_VERBS,
        _extract_tx_params,
        _is_contract_search_attempt,
        _is_financial_tool_call,
        _is_policy_tampering_attempt,
        _iter_strings,
        _references_protected_path,
        on_pre_tool_call,
    )
    from .commands import (
        _parse_command_args,
        safeguard_allow_command_handler,
        safeguard_audit_command_handler,
        safeguard_balanced_command_handler,
        safeguard_check_command_handler,
        safeguard_confirm_command_handler,
        safeguard_connect_tg_command_handler,
        safeguard_degen_command_handler,
        safeguard_exec_command_handler,
        safeguard_help_command_handler,
        safeguard_mint_command_handler,
        safeguard_mode_command_handler,
        safeguard_panic_command_handler,
        safeguard_pending_command_handler,
        safeguard_reject_command_handler,
        safeguard_resume_command_handler,
        safeguard_revoke_command_handler,
        safeguard_status_handler,
        safeguard_strict_command_handler,
        safeguard_sync_command_handler,
        safeguard_test_alert_command_handler,
        safeguard_threats_command_handler,
        safeguard_tx_command_handler,
        safeguard_whitelist_command_handler,
        safeguard_scan_command_handler,
        safeguard_ingest_command_handler,
    )
    from .storage import (
        get_plugin_data_dir,
        read_state_file,
        resolve_state_path,
        unlink_state_file,
        write_state_file,
    )
    from .verifier import ensure_test_rpc_server
except (ImportError, ValueError):
    from schemas import (
        ALL_TOOL_SCHEMAS,
        MINT_NFT_SCHEMA,
        SAFEGUARD_CHECK_POLICY_SCHEMA,
        SAFEGUARD_EXECUTE_TX_SCHEMA,
    )
    from tools import (
        _get_policy_config,
        _notify_telegram_operator,
        is_kill_switch_active,
        mint_nft_handler,
        safeguard_check_policy_handler,
        safeguard_confirm_action_handler,
        safeguard_execute_tx_handler,
        set_kill_switch,
    )
    from hooks import (
        FINANCIAL_NAME_KEYWORDS,
        PROTECTED_BASENAMES,
        SAFEGUARD_INTERNAL_TOOLS,
        _COMMAND_VERBS,
        _ETH_ADDRESS_REGEX,
        _MUTATING_VERBS,
        _extract_tx_params,
        _is_contract_search_attempt,
        _is_financial_tool_call,
        _is_policy_tampering_attempt,
        _iter_strings,
        _references_protected_path,
        on_pre_tool_call,
    )
    from commands import (
        _parse_command_args,
        safeguard_allow_command_handler,
        safeguard_audit_command_handler,
        safeguard_balanced_command_handler,
        safeguard_check_command_handler,
        safeguard_confirm_command_handler,
        safeguard_connect_tg_command_handler,
        safeguard_degen_command_handler,
        safeguard_exec_command_handler,
        safeguard_help_command_handler,
        safeguard_mint_command_handler,
        safeguard_mode_command_handler,
        safeguard_panic_command_handler,
        safeguard_pending_command_handler,
        safeguard_reject_command_handler,
        safeguard_resume_command_handler,
        safeguard_revoke_command_handler,
        safeguard_status_handler,
        safeguard_strict_command_handler,
        safeguard_sync_command_handler,
        safeguard_test_alert_command_handler,
        safeguard_threats_command_handler,
        safeguard_tx_command_handler,
        safeguard_whitelist_command_handler,
        safeguard_scan_command_handler,
        safeguard_ingest_command_handler,
    )
    from storage import (
        get_plugin_data_dir,
        read_state_file,
        resolve_state_path,
        unlink_state_file,
        write_state_file,
    )
    from verifier import ensure_test_rpc_server

logger = logging.getLogger("hermes-safeguard")


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

    # 1. Official Hermes Agent signature: name, toolset, schema, handler
    for ts in (toolset, "safeguard", "default"):
        try:
            reg_fn(name=name, toolset=ts, schema=full_schema, handler=handler)
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
    Registration runs without starting threads, daemons, or network calls.
    """
    # 1. Register tool: safeguard_check_policy
    _register_tool_safely(
        ctx=ctx,
        name="safeguard_check_policy",
        handler=safeguard_check_policy_handler,
        description=SAFEGUARD_CHECK_POLICY_SCHEMA["description"],
        parameters=SAFEGUARD_CHECK_POLICY_SCHEMA["parameters"],
        toolset="hermes-safeguard",
    )

    # 2. Register tool: safeguard_execute_tx
    _register_tool_safely(
        ctx=ctx,
        name="safeguard_execute_tx",
        handler=safeguard_execute_tx_handler,
        description=SAFEGUARD_EXECUTE_TX_SCHEMA["description"],
        parameters=SAFEGUARD_EXECUTE_TX_SCHEMA["parameters"],
        toolset="hermes-safeguard",
    )

    # 3. Register tool: mint_nft
    _register_tool_safely(
        ctx=ctx,
        name="mint_nft",
        handler=mint_nft_handler,
        description=MINT_NFT_SCHEMA["description"],
        parameters=MINT_NFT_SCHEMA["parameters"],
        toolset="hermes-safeguard",
    )

    # 4. Register hook: pre_tool_call
    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    # 5. Register slash commands
    cmd_handlers = {
        # Direct execution commands
        "safeguard-tx": safeguard_tx_command_handler,
        "safegaurd-tx": safeguard_tx_command_handler,
        "safeguard-mint": safeguard_mint_command_handler,
        "safegaurd-mint": safeguard_mint_command_handler,
        "safeguard-exec": safeguard_exec_command_handler,
        "safegaurd-exec": safeguard_exec_command_handler,
        "safeguard-scan": safeguard_scan_command_handler,
        "safeguard-ingest": safeguard_ingest_command_handler,

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
        "safeguard-approve": safeguard_confirm_command_handler,
        "safeguard-reject": safeguard_reject_command_handler,
        "confirm": safeguard_confirm_command_handler,
        "reject": safeguard_reject_command_handler,
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
        "safeguard-tx": "Zero-overhead instant on-chain execution under SafeGuard EVM simulation (e.g. /safeguard-tx <addr> <eth> [data_hex]).",
        "safegaurd-tx": "Zero-overhead instant on-chain execution under SafeGuard EVM simulation (alias).",
        "safeguard-mint": "Directly mint NFT under SafeGuard EVM simulation protection (e.g. /safeguard-mint <addr> [eth]).",
        "safegaurd-mint": "Directly mint NFT under SafeGuard EVM simulation protection (alias).",
        "safeguard-exec": "Directly execute on-chain transaction under SafeGuard EVM simulation (e.g. /safeguard-exec <addr> [eth] [hex]).",
        "safegaurd-exec": "Directly execute on-chain transaction under SafeGuard EVM simulation (alias).",
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
                    if cmd_name in registered_cmds:
                        continue
                    desc = cmd_descriptions.get(cmd_base, "")
                    try:
                        reg_fn(
                            name=cmd_name,
                            handler=handler,
                            description=desc,
                        )
                        registered_cmds.add(cmd_name)
                    except TypeError:
                        try:
                            reg_fn(cmd_name, handler, desc)
                            registered_cmds.add(cmd_name)
                        except TypeError:
                            try:
                                reg_fn(cmd_name, handler)
                                registered_cmds.add(cmd_name)
                            except Exception:
                                pass
                        except Exception:
                            pass
                    except Exception:
                        pass

    # 6. Register one-line routing rule instructing the agent to route transactions cleanly
    routing_rule = (
        "Route all 0x addresses and transaction intents (send, mint, swap, approve, transfer, tx, contract) "
        "directly to `safeguard_execute_tx` without searching local files, and request operator approval before broadcast."
    )
    for rule_fn_name in ("register_routing_rule", "register_rule", "register_prompt_rule", "add_rule"):
        rule_fn = getattr(ctx, rule_fn_name, None)
        if callable(rule_fn):
            try:
                rule_fn("safeguard.onchain_routing", routing_rule)
                break
            except TypeError:
                try:
                    rule_fn(routing_rule)
                    break
                except Exception:
                    pass
            except Exception:
                pass

    # 7. Register system prompt section so Hermes Agent simulates transactions and asks for approval
    sys_prompt_fn = getattr(ctx, "register_system_prompt_section", None)
    if callable(sys_prompt_fn):
        prompt_content = (
            "Hermes SafeGuard security middleware is active. "
            "SafeGuard simulates EVM transactions and requests operator approval before broadcast.\n\n"
            "TRANSACTION SIMULATION & APPROVAL WORKFLOW:\n"
            "When executing an on-chain transaction or minting:\n"
            "1. Invoke `safeguard_execute_tx(to=..., value=..., data=...)` to simulate the transaction.\n"
            "2. SafeGuard evaluates the transaction and requests operator approval.\n\n"
            "SafeGuard Slash Commands:\n"
            "  /safeguard-tx <to> <eth> [data] - Execute on-chain transaction under SafeGuard protection\n"
            "  /safeguard-mode [strict|balanced] - View or switch policy mode\n"
            "  /safeguard-strict, /safeguard-balanced - Quick mode switch\n"
            "  /safeguard-status - View current mode, limits, and connection status\n"
            "  /safeguard-pending - View pending confirmations\n"
            "  /safeguard-confirm <id> - Approve held transaction\n"
            "  /safeguard-reject <id> - Reject held transaction\n"
            "  /safeguard-whitelist - View approved addresses\n"
            "  /safeguard-allow <addr> [label] - Pre-approve address\n"
            "  /safeguard-check <addr> - Check address reputation\n"
            "  /safeguard-help - View command help"
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
    # Threat stream sync and servers remain lazy: initialized on explicit command (/safeguard-sync)
    # or on first policy check, preserving zero side-effects during registration.
