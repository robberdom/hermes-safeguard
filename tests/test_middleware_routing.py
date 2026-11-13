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
        """
        Filesystem tools whose arguments name an on-chain contract address are
        redirected with the 'on-chain smart contract' directive.

        The former intent-only blocker (which refused any file read/search whenever
        the chat context merely *mentioned* a mint/swap/transfer) was intentionally
        removed in the PR review refactor; those calls are now permitted.
        """
        addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        directive = "is an on-chain smart contract on Ethereum, NOT a local codebase file"

        # Case 1: grep with a full contract address -> redirected
        res1 = hooks.on_pre_tool_call("grep", {"pattern": addr})
        self.assertEqual(res1.get("action"), "block")
        self.assertIn(directive, res1.get("message", ""))
        self.assertIn(addr, res1.get("message", ""))
        self.assertFalse(bool(res1))

        # Case 2: read_file while the user context names the contract -> redirected
        res2 = hooks.on_pre_tool_call(
            "read_file",
            {"path": "contracts/DegenNFT.sol"},
            context=[{"role": "user", "content": f"Mint 1 NFT from {addr} for 0.05 ETH"}],
        )
        self.assertEqual(res2.get("action"), "block")
        self.assertIn(directive, res2.get("message", ""))

        # Case 3: intent keywords alone no longer block ordinary filesystem work
        intent_only = [
            (("search_files", {"query": "mint"}), {}),
            (("list_dir", {"path": "contracts"}),
             {"context": [{"role": "user", "content": "Transfer 1 ETH to 0x1111222233334444555566667777888899990000"}]}),
            (("find", {"name": "*.sol"}),
             {"context": [{"role": "user", "content": "Swap 0.5 ETH on Uniswap"}]}),
            (("bash", {"command": "grep -rn 0x5FbDB ."}), {}),
            (("terminal", {"command": "cat contracts/DegenNFT.sol"}),
             {"context": [{"role": "user", "content": f"Approve {addr} for 1000 tokens"}]}),
        ]
        for (tool, args), kw in intent_only:
            with self.subTest(tool=tool, args=args):
                self.assertEqual(hooks.on_pre_tool_call(tool, args, **kw).get("action"), "allow")

        # Case 4: Non-onchain file read is permitted
        res4 = hooks.on_pre_tool_call(
            "read_file",
            {"path": "README.md"},
            context=[{"role": "user", "content": "Explain project architecture and docs"}],
        )
        self.assertEqual(res4.get("action"), "allow")

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
