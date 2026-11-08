#!/usr/bin/env python3
"""
test_plugin.py — Verify Hermes SafeGuard plugin registration, tools, and hooks.
"""

import json
import __init__ as safeguard
from verifier import (
    ensure_test_rpc_server,
    APPROVE_SELECTOR,
    encode_address_word,
    encode_uint256_word,
    UINT256_MAX,
)


def run_tests():
    print("=== Testing Hermes SafeGuard Plugin ===")

    # 1. Start local fallback RPC simulation server if Anvil is not active
    ensure_test_rpc_server("127.0.0.1", 8545)

    # 2. Test registration in official Hermes PluginContext and legacy mock context
    class HermesPluginContext:
        """Mimics official NousResearch/hermes-agent PluginContext signature."""
        def __init__(self):
            self.tools = {}
            self.hooks = {}
            self.commands = {}

        def register_tool(
            self,
            name,
            toolset,
            schema,
            handler,
            check_fn=None,
            requires_env=None,
            is_async=False,
            description="",
            emoji="",
            override=False,
        ):
            self.tools[name] = {
                "toolset": toolset,
                "schema": schema,
                "handler": handler,
                "override": override,
            }

        def register_hook(self, name, handler):
            self.hooks[name] = handler

        def register_command(self, name, handler, description="", args_hint="", argument_mode=None):
            self.commands[name] = handler

    h_ctx = HermesPluginContext()
    safeguard.register(h_ctx)
    assert "safeguard_check_policy" in h_ctx.tools, "safeguard_check_policy not registered in HermesPluginContext"
    assert "safeguard_execute_tx" in h_ctx.tools, "safeguard_execute_tx not registered in HermesPluginContext"
    assert h_ctx.tools["safeguard_check_policy"]["toolset"] == "hermes-safeguard"
    assert h_ctx.tools["safeguard_check_policy"]["schema"]["name"] == "safeguard_check_policy"
    assert "safeguard-status" in h_ctx.commands, "safeguard-status not registered in HermesPluginContext"
    assert "pre_tool_call" in h_ctx.hooks, "pre_tool_call hook not registered in HermesPluginContext"
    print("[PASS] Registration (HermesPluginContext): tools, hooks, and slash command registered correctly.")

    class MockContext:
        def __init__(self):
            self.tools = {}
            self.hooks = {}
            self.commands = {}

        def register_tool(self, name, description, parameters, handler):
            self.tools[name] = {"desc": description, "params": parameters, "handler": handler}

        def register_hook(self, name, handler):
            self.hooks[name] = handler

        def register_command(self, name, handler, description=""):
            self.commands[name] = handler

    ctx = MockContext()
    safeguard.register(ctx)
    assert "safeguard_check_policy" in ctx.tools, "safeguard_check_policy not registered"
    assert "safeguard_execute_tx" in ctx.tools, "safeguard_execute_tx not registered"
    assert "pre_tool_call" in ctx.hooks, "pre_tool_call hook not registered"
    assert "safeguard-status" in ctx.commands or "/safeguard-status" in ctx.commands
    print("[PASS] Registration (Legacy MockContext): tools, hooks, and commands registered correctly.")

    class KwargsContext:
        def __init__(self):
            self.calls = []

        def register_tool(self, name, **kwargs):
            self.calls.append(kwargs)

    kwargs_ctx = KwargsContext()
    safeguard._register_tool_safely(
        kwargs_ctx,
        name="safeguard_test",
        handler=lambda: None,
        description="Test generic kwargs registration",
    )
    assert all("parameters" not in call for call in kwargs_ctx.calls)
    print("[PASS] Registration does not infer legacy parameters support from **kwargs.")

    # 3. Test Test 1: Hook blocks an unlimited ERC-20 approval in balanced mode
    unlimited_approve_calldata = (
        "0x"
        + APPROVE_SELECTOR
        + encode_address_word("0x0000000000000000000000000000000000000001").hex()
        + encode_uint256_word(UINT256_MAX).hex()
    )

    hook_res = safeguard.on_pre_tool_call(
        "approve",
        {
            "to": "0x000000000000000000000000000000000000c001",
            "data": unlimited_approve_calldata,
            "mode": "balanced",
        },
    )
    assert hook_res["action"] == "block", f"Expected block, got: {hook_res}"
    assert "unbounded approve blocked" in hook_res["message"]
    print("[PASS] Test 1: Unlimited approve correctly blocked by pre_tool_call hook in balanced mode.")

    # 4. Test Test 2: Hook blocks transaction to known malicious threat address in degen mode
    drain_res = safeguard.on_pre_tool_call(
        "eth_sendTransaction",
        {
            "to": "0x000000000000000000000000000000000000bad1",  # Verified drain contract in blocklist.json
            "value": 0,
            "mode": "degen",
        },
    )
    assert drain_res["action"] == "block", f"Expected block, got: {drain_res}"
    assert drain_res["risk_score"] == "critical"
    print("[PASS] Test 2: Known drainer target hard-blocked in degen mode.")

    # 5. Test 3: Safe transaction passes
    safe_res = safeguard.on_pre_tool_call(
        "send_transaction",
        {
            "to": "0x000000000000000000000000000000000000beef",
            "value": 10**17,  # 0.1 ETH
            "mode": "balanced",
        },
    )
    assert safe_res["action"] in ("allow", "approve"), f"Expected allow/approve, got: {safe_res}"
    print("[PASS] Test 3: Legitimate transaction allowed.")

    # 6. Test 4: Slash command status output
    status_output = safeguard.safeguard_status_handler()
    assert "SafeGuard Status" in status_output
    print("[PASS] Test 4: /safeguard-status returned status successfully.")

    print("\nAll plugin verification tests passed successfully!")


if __name__ == "__main__":
    run_tests()

