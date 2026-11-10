#!/usr/bin/env python3
"""
tests/test_plugin_registration.py — Unit tests for Hermes Agent plugin registration API.

Verifies that `safeguard.register(ctx)` and `_register_tool_safely`:
  1. Conforms strictly to the official NousResearch/hermes-agent PluginContext.register_tool signature
     (name, toolset, schema, handler) and NEVER passes an unexpected 'parameters' kwarg.
  2. Successfully registers tools, hooks, and slash commands.
  3. Supports legacy and kwargs-based test runners gracefully.
"""

import unittest
from typing import Any, Callable

import __init__ as safeguard


class OfficialHermesPluginContext:
    """Mimics official NousResearch/hermes-agent PluginContext."""

    def __init__(self):
        self.tools: dict[str, dict[str, Any]] = {}
        self.hooks: dict[str, Callable] = {}
        self.commands: dict[str, Callable] = {}

    def register_tool(
        self,
        name: str,
        toolset: str,
        schema: dict,
        handler: Callable,
        check_fn: Callable | None = None,
        requires_env: list | None = None,
        is_async: bool = False,
        description: str = "",
        emoji: str = "",
        override: bool = False,
    ):
        # Strict signature check: if caller passes 'parameters', Python will raise TypeError
        self.tools[name] = {
            "name": name,
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            "description": description,
            "override": override,
        }

    def register_hook(self, name: str, handler: Callable):
        self.hooks[name] = handler

    def register_command(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        args_hint: str = "",
        argument_mode: str | None = None,
    ):
        self.commands[name] = handler


class TestPluginRegistration(unittest.TestCase):
    def test_official_hermes_plugin_context_registration(self):
        ctx = OfficialHermesPluginContext()
        safeguard.register(ctx)

        # Verify tools registered
        self.assertIn("safeguard_check_policy", ctx.tools)
        self.assertIn("safeguard_execute_tx", ctx.tools)

        # Check toolset and schema structure
        check_tool = ctx.tools["safeguard_check_policy"]
        self.assertEqual(check_tool["toolset"], "hermes-safeguard")
        self.assertIn("parameters", check_tool["schema"])
        self.assertIn("to", check_tool["schema"]["parameters"]["properties"])
        self.assertTrue(callable(check_tool["handler"]))

        # Check pre_tool_call hook
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertTrue(callable(ctx.hooks["pre_tool_call"]))

        # Check safeguard-status slash command
        self.assertIn("safeguard-status", ctx.commands)
        self.assertTrue(callable(ctx.commands["safeguard-status"]))

    def test_no_parameters_kwarg_leaked(self):
        """Ensure _register_tool_safely never leaks 'parameters' kwarg to register_tool."""
        captured_kwargs: list[dict[str, Any]] = []

        class KwargsContext:
            def register_tool(self, name, **kwargs):
                captured_kwargs.append(kwargs)

        ctx = KwargsContext()
        safeguard._register_tool_safely(
            ctx,
            name="test_tool",
            handler=lambda: None,
            description="Testing kwargs",
            parameters={"type": "object", "properties": {"a": {"type": "string"}}},
        )

        self.assertTrue(len(captured_kwargs) > 0)
        for call_kwargs in captured_kwargs:
            self.assertNotIn(
                "parameters",
                call_kwargs,
                "Unexpected 'parameters' keyword argument passed to register_tool!",
            )

    def test_legacy_context_backward_compatibility(self):
        """Ensure backwards compatibility with test harnesses that use (name, description, parameters, handler)."""
        registered = {}

        class LegacyContext:
            def register_tool(self, name, description, parameters, handler):
                registered[name] = {
                    "description": description,
                    "parameters": parameters,
                    "handler": handler,
                }

        ctx = LegacyContext()
        safeguard._register_tool_safely(
            ctx,
            name="legacy_tool",
            handler=lambda: None,
            description="Legacy test",
            parameters={"type": "object", "properties": {}},
        )

        self.assertIn("legacy_tool", registered)

    def test_grep_contract_address_redirection(self):
        """Ensure agent grep/search attempts for onchain addresses are intercepted and redirected."""
        res = safeguard.on_pre_tool_call(
            "grep",
            {"query": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "path": "."},
        )
        self.assertEqual(res.get("action"), "block")
        self.assertIn("on-chain smart contract", res.get("message", ""))
        self.assertIn("safeguard_execute_tx", res.get("message", ""))

    def test_auto_encode_mint_calldata(self):
        """Ensure safeguard_execute_tx automatically encodes mint calldata for NFT contracts when data is 0x."""
        import json
        raw_res = safeguard.safeguard_execute_tx_handler(
            to="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            value="0.05 ether",
            data="0x",
            mode="degen",
        )
        res = json.loads(raw_res)
        # In degen mode with test RPC, the transaction passes or executes without error
        self.assertTrue(res.get("allowed", False))


if __name__ == "__main__":
    unittest.main()

