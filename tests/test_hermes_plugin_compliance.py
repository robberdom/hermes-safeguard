"""
Test Hermes Agent Plugin Architecture Compliance.
Verifies compliance with https://hermes-agent.nousresearch.com/docs/developer-guide/plugins:
1. 4-file architecture: plugin.yaml, schemas.py, tools.py, __init__.py
2. Separation of concerns:
   - Manifest declares what the plugin is
   - Schemas describe tools for the LLM
   - Handlers implement the actual logic
   - Registration connects everything
3. Handlers accept **kwargs and return valid JSON strings
4. State storage persists via plugin_data_dir() without writing runtime state into the install tree
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
import storage
import tools


class TestHermesPluginCompliance(unittest.TestCase):
    def setUp(self):
        self.repo_dir = Path(__file__).resolve().parent.parent

    def test_four_file_structure_exists(self):
        """Verify the 4 canonical plugin files exist in the root."""
        plugin_yaml = self.repo_dir / "plugin.yaml"
        init_py = self.repo_dir / "__init__.py"
        schemas_py = self.repo_dir / "schemas.py"
        tools_py = self.repo_dir / "tools.py"

        self.assertTrue(plugin_yaml.is_file(), "plugin.yaml must exist at plugin root")
        self.assertTrue(init_py.is_file(), "__init__.py must exist at plugin root")
        self.assertTrue(schemas_py.is_file(), "schemas.py must exist at plugin root")
        self.assertTrue(tools_py.is_file(), "tools.py must exist at plugin root")

    def test_plugin_yaml_manifest_declarations(self):
        """Verify plugin.yaml specifies required metadata, tools, hooks, and commands."""
        plugin_yaml = self.repo_dir / "plugin.yaml"
        data = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))

        self.assertEqual(data.get("name"), "hermes-safeguard")
        self.assertIn("version", data)
        self.assertIn("description", data)

        tools_list = data.get("provides_tools", [])
        self.assertIn("safeguard_check_policy", tools_list)
        self.assertIn("safeguard_execute_tx", tools_list)
        self.assertIn("mint_nft", tools_list)

        hooks_list = data.get("provides_hooks", [])
        self.assertIn("pre_tool_call", hooks_list)

        env_list = data.get("requires_env", [])
        env_names = [e["name"] if isinstance(e, dict) else e for e in env_list]
        self.assertIn("SAFEGUARD_RPC_URL", env_names)
        # Bot token is namespaced and declared secret so Hermes routes it via the secret scope
        self.assertIn("SAFEGUARD_TELEGRAM_BOT_TOKEN", env_names)
        self.assertNotIn("TELEGRAM_BOT_TOKEN", env_names)
        token_entry = next(e for e in env_list if isinstance(e, dict) and e.get("name") == "SAFEGUARD_TELEGRAM_BOT_TOKEN")
        self.assertTrue(token_entry.get("secret"))

        # Hermes reads Python requirements from python_dependencies (PR review — Issue 8)
        self.assertIn("pyyaml>=6.0", data.get("python_dependencies", []))
        self.assertNotIn("dependencies", data)

    def test_schemas_match_declared_tools(self):
        """Verify schemas.py defines schemas for all declared tools with valid JSON schema properties."""
        for tool_name in ["safeguard_check_policy", "safeguard_execute_tx", "mint_nft"]:
            self.assertIn(tool_name, schemas.ALL_TOOL_SCHEMAS)
            schema = schemas.ALL_TOOL_SCHEMAS[tool_name]
            self.assertEqual(schema["name"], tool_name)
            self.assertIn("description", schema)
            self.assertIn("parameters", schema)
            self.assertEqual(schema["parameters"].get("type"), "object")
            self.assertIn("properties", schema["parameters"])
            self.assertIn("required", schema["parameters"])

    def test_tool_handlers_return_valid_json_and_accept_kwargs(self):
        """Verify tool handlers accept **kwargs and return valid JSON strings."""
        handlers = [
            (tools.safeguard_check_policy_handler, {"to": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "unexpected_arg": "ignore_me"}),
            (tools.safeguard_execute_tx_handler, {"to": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "unexpected_arg": "ignore_me"}),
            (tools.mint_nft_handler, {"to": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "unexpected_arg": "ignore_me"}),
        ]

        for handler, test_kwargs in handlers:
            ret = handler(**test_kwargs)
            self.assertIsInstance(ret, str, f"{handler.__name__} must return serialized JSON string")
            parsed = json.loads(ret)
            self.assertIsInstance(parsed, dict, f"{handler.__name__} payload must parse as dict")

    def test_storage_resolves_plugin_data_dir(self):
        """Verify storage module resolves persistent data dir."""
        data_dir = storage.get_plugin_data_dir()
        self.assertIsInstance(data_dir, Path)
        self.assertTrue(data_dir.is_dir() or data_dir.exists())

        path = storage.resolve_state_path(".safeguard_mode")
        self.assertEqual(path.name, ".safeguard_mode")
        self.assertEqual(path.parent, data_dir)

    def test_registration_wiring(self):
        """Verify register(ctx) wires schemas, handlers, hooks, and commands."""
        class MockPluginContext:
            def __init__(self):
                self.registered_tools = {}
                self.registered_hooks = {}
                self.registered_commands = {}

            def register_tool(self, name, toolset, schema, handler, **kwargs):
                self.registered_tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

            def register_hook(self, name, handler):
                self.registered_hooks[name] = handler

            def register_command(self, name, handler, description="", **kwargs):
                self.registered_commands[name] = handler

        ctx = MockPluginContext()
        safeguard.register(ctx)

        # Tools
        self.assertIn("safeguard_check_policy", ctx.registered_tools)
        self.assertIn("safeguard_execute_tx", ctx.registered_tools)
        self.assertIn("mint_nft", ctx.registered_tools)

        # Check schemas were wired directly from schemas.py
        self.assertEqual(
            ctx.registered_tools["safeguard_check_policy"]["schema"]["description"],
            schemas.SAFEGUARD_CHECK_POLICY_SCHEMA["description"]
        )

        # Hooks
        self.assertIn("pre_tool_call", ctx.registered_hooks)
        self.assertEqual(ctx.registered_hooks["pre_tool_call"], hooks.on_pre_tool_call)

        # Commands
        self.assertIn("safeguard-mode", ctx.registered_commands)
        self.assertIn("safeguard-status", ctx.registered_commands)
        self.assertIn("safeguard-confirm", ctx.registered_commands)


if __name__ == "__main__":
    unittest.main()
