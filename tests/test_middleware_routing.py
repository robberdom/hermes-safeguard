"""
Test Hermes SafeGuard Middleware Routing and Fast-Path Fixes:
1. File search blocking in pre_tool_call on onchain intent
2. Tightened tool schema triggers & routing rule in register(ctx)
3. Direct middleware slash command (/safeguard-tx)
"""

import json
import sys
import unittest
from pathlib import Path

_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import yaml

import __init__ as safeguard
import commands
import hooks
import schemas


class MockPluginContext:
    def __init__(self):
        self.registered_tools = {}
        self.registered_hooks = {}
        self.registered_commands = {}
        self.rules = []
        self.system_prompt_sections = {}

    def register_tool(self, name, toolset, schema, handler, **kwargs):
        self.registered_tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_hook(self, name, handler):
        self.registered_hooks[name] = handler

    def register_command(self, name, handler, description="", **kwargs):
        self.registered_commands[name] = handler

    def register_routing_rule(self, name, rule):
        self.rules.append(rule)

    def register_system_prompt_section(self, name, content, **kwargs):
        self.system_prompt_sections[name] = content


class TestMiddlewareRouting(unittest.TestCase):
    def test_pre_tool_call_blocks_file_searches_on_onchain_intent(self):
        expected_msg = "SAFEGUARD MIDDLEWARE: File search blocked for onchain intent. Invoke safeguard_execute_tx immediately."

        # Case 1: grep with 0x address
        res1 = hooks.on_pre_tool_call("grep", {"pattern": "0x5FbDB2315678afecb367f032d93F642f64180aa3"})
        self.assertEqual(res1.get("action"), "block")
        self.assertEqual(res1.get("message"), expected_msg)
        self.assertFalse(bool(res1))

        # Case 2: search_files with mint keyword
        res2 = hooks.on_pre_tool_call("search_files", {"query": "mint"})
        self.assertEqual(res2.get("action"), "block")
        self.assertEqual(res2.get("message"), expected_msg)

        # Case 3: read_file with user context containing onchain mint intent
        res3 = hooks.on_pre_tool_call(
            "read_file",
            {"path": "contracts/DegenNFT.sol"},
            context=[{"role": "user", "content": "Mint 1 NFT from 0x5FbDB2315678afecb367f032d93F642f64180aa3 for 0.05 ETH"}],
        )
        self.assertEqual(res3.get("action"), "block")
        self.assertEqual(res3.get("message"), expected_msg)

        # Case 4: list_dir with user context containing transfer intent
        res4 = hooks.on_pre_tool_call(
            "list_dir",
            {"path": "contracts"},
            context=[{"role": "user", "content": "Transfer 1 ETH to 0x1111222233334444555566667777888899990000"}],
        )
        self.assertEqual(res4.get("action"), "block")
        self.assertEqual(res4.get("message"), expected_msg)

        # Case 5: find with user context containing swap intent
        res5 = hooks.on_pre_tool_call(
            "find",
            {"name": "*.sol"},
            context=[{"role": "user", "content": "Swap 0.5 ETH on Uniswap"}],
        )
        self.assertEqual(res5.get("action"), "block")
        self.assertEqual(res5.get("message"), expected_msg)

        # Case 6: bash running grep with 0x address
        res6 = hooks.on_pre_tool_call("bash", {"command": "grep -rn 0x5FbDB ."})
        self.assertEqual(res6.get("action"), "block")
        self.assertEqual(res6.get("message"), expected_msg)

        # Case 7: terminal running cat with approve intent in context
        res7 = hooks.on_pre_tool_call(
            "terminal",
            {"command": "cat contracts/DegenNFT.sol"},
            context=[{"role": "user", "content": "Approve 0x5FbDB2315678afecb367f032d93F642f64180aa3 for 1000 tokens"}],
        )
        self.assertEqual(res7.get("action"), "block")
        self.assertEqual(res7.get("message"), expected_msg)

        # Case 8: Non-onchain file read is permitted
        res8 = hooks.on_pre_tool_call(
            "read_file",
            {"path": "README.md"},
            context=[{"role": "user", "content": "Explain project architecture and docs"}],
        )
        self.assertEqual(res8.get("action"), "allow")

    def test_tool_schema_descriptions_and_routing_rule(self):
        # 1. Check schemas.py descriptions contain required triggers
        keywords = ["send", "mint", "swap", "approve", "transfer", "0x", "contract", "tx"]
        for tool_name in ("safeguard_execute_tx", "safeguard_check_policy"):
            desc = schemas.ALL_TOOL_SCHEMAS[tool_name]["description"].lower()
            for kw in keywords:
                self.assertIn(kw, desc, f"Keyword '{kw}' missing from {tool_name} description in schemas.py")

        # 2. Check plugin.yaml tool metadata
        plugin_yaml = Path(__file__).resolve().parent.parent / "plugin.yaml"
        manifest = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        for tool_name in ("safeguard_execute_tx", "safeguard_check_policy"):
            desc = manifest["tools"][tool_name]["description"].lower()
            for kw in keywords:
                self.assertIn(kw, desc, f"Keyword '{kw}' missing from {tool_name} description in plugin.yaml")

        # 3. Check register(ctx) registers the routing rule
        ctx = MockPluginContext()
        safeguard.register(ctx)
        self.assertTrue(len(ctx.rules) > 0, "A routing rule must be registered in ctx")
        rule_text = ctx.rules[0].lower()
        self.assertIn("0x", rule_text)
        self.assertIn("safeguard_execute_tx", rule_text)

    def test_safeguard_tx_slash_command(self):
        ctx = MockPluginContext()
        safeguard.register(ctx)

        # Registered in commands
        self.assertIn("safeguard-tx", ctx.registered_commands)
        self.assertIn("/safeguard-tx", ctx.registered_commands)

        # Execute on malicious drainer (must hard-block instantly)
        blocked_res = commands.safeguard_tx_command_handler(
            "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 0 0xd8a17684"
        )
        self.assertIn("BLOCKED", blocked_res)
        self.assertIn("drain", blocked_res.lower())

        # Empty usage message
        empty_res = commands.safeguard_tx_command_handler("")
        self.assertIn("Usage: /safeguard-tx", empty_res)


if __name__ == "__main__":
    unittest.main()
