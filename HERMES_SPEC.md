# Hermes Agent Plugin Specification Reference

Hermes loads plugins from directories containing `plugin.yaml` and `__init__.py` with entrypoint `def register(ctx):`.

Source reference: `https://hermes-agent.nousresearch.com/docs/developer-guide/plugins`

---

## 1. Directory Structure

```text
hermes-safeguard/
├── plugin.yaml          # Plugin manifest
├── __init__.py          # Plugin registration entrypoint
├── contracts/           # Foundry Solidity policy contracts
│   ├── src/SafeGuardPolicy.sol
│   └── test/SafeGuardPolicy.t.sol
├── keys/                # Encrypted local keystore storage
│   └── keystore.json.enc
└── tests/               # Unit and integration tests
```

---

## 2. Manifest Schema (`plugin.yaml`)

```yaml
name: hermes-safeguard
version: "1.0.0"
description: Policy-bounded transaction verification and security middleware for onchain agent actions.
author: pohtaytohpohtahtoh
requires_hermes: ">=0.22.0"
provides_tools:
  - safeguard_check_policy
  - safeguard_execute_tx
provides_hooks:
  - pre_tool_call
  - post_tool_call
provides_commands:
  - safeguard-help
  - safeguard-status
  - safeguard-mode
  - safeguard-strict
  - safeguard-balanced
  - safeguard-degen
  - safeguard-pending
  - safeguard-confirm
  - safeguard-reject
  - safeguard-whitelist
  - safeguard-allow
  - safeguard-revoke
  - safeguard-check
  - safeguard-threats
  - safeguard-sync
  - safeguard-test-alert
  - safeguard-panic
  - safeguard-resume
  - safeguard-audit
  - safegaurd-mode
capabilities:
  - tools.override
```

### Manifest Rules
- `provides_tools`: Must exactly match names passed to `ctx.register_tool()`.
- `provides_hooks`: Must match event names passed to `ctx.register_hook()`.
- `provides_commands`: Lists interactive in-session slash commands registered via `ctx.register_command()`.
- `capabilities`: Must explicitly declare `tools.override` when overriding or intercepting default transaction tools.
- Validation command: `hermes plugins validate . --install-deps` checks manifest consistency, public API imports, and capabilities.

---

## 3. Plugin Context API (`ctx`)

Inside `def register(ctx):`:

### Tool Registration
```python
ctx.register_tool(
    name="safeguard_check_policy",
    toolset="hermes-safeguard",
    schema={
        "name": "safeguard_check_policy",
        "description": "Simulate and verify an onchain transaction against SafeGuard policies without signing.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Target address"},
                "value": {"type": "string", "description": "ETH value in wei or ether"},
                "data": {"type": "string", "description": "Call data hex string"},
            },
            "required": ["to"],
        },
    },
    handler=safeguard_check_policy_handler,
    description="Simulate and verify an onchain transaction against SafeGuard policies without signing.",
    override=True,
)
```

### Slash Command Registration
```python
# Mode management (cycle or set directly)
ctx.register_command("safeguard-mode", safeguard_mode_command_handler, "Switch or cycle SafeGuard policy mode.")
ctx.register_command("safeguard-strict", safeguard_strict_command_handler, "Switch to strict mode.")
ctx.register_command("safeguard-balanced", safeguard_balanced_command_handler, "Switch to balanced mode.")
ctx.register_command("safeguard-degen", safeguard_degen_command_handler, "Switch to degen mode.")

# Diagnostics & help
ctx.register_command("safeguard-status", safeguard_status_handler, "Display SafeGuard status and limits.")
ctx.register_command("safeguard-help", safeguard_help_command_handler, "Display SafeGuard slash command reference.")
ctx.register_command("safeguard-threats", safeguard_threats_command_handler, "Display threat intelligence status.")
ctx.register_command("safeguard-audit", safeguard_audit_command_handler, "Display recent audit decisions.")

# Human-in-the-loop confirmations
ctx.register_command("safeguard-pending", safeguard_pending_command_handler, "List pending held transactions.")
ctx.register_command("safeguard-confirm", safeguard_confirm_command_handler, "Approve a held transaction by ID.")
ctx.register_command("safeguard-reject", safeguard_reject_command_handler, "Reject a held transaction by ID.")

# Address memory & whitelist
ctx.register_command("safeguard-whitelist", safeguard_whitelist_command_handler, "List approved addresses.")
ctx.register_command("safeguard-allow", safeguard_allow_command_handler, "Pre-approve a trusted address.")
ctx.register_command("safeguard-revoke", safeguard_revoke_command_handler, "Revoke approval for an address.")
ctx.register_command("safeguard-check", safeguard_check_command_handler, "Check address against threat feeds.")

# Threats, sync & emergency kill-switch
ctx.register_command("safeguard-threats", safeguard_threats_command_handler, "View threat feed stats.")
ctx.register_command("safeguard-sync", safeguard_sync_command_handler, "Sync threat intelligence feeds.")
ctx.register_command("safeguard-test-alert", safeguard_test_alert_command_handler, "Verify alert connectivity.")
ctx.register_command("safeguard-panic", safeguard_panic_command_handler, "Engage emergency kill-switch.")
ctx.register_command("safeguard-resume", safeguard_resume_command_handler, "Release emergency kill-switch.")
```

### System Prompt Injection
```python
ctx.register_system_prompt_section(
    "safeguard.guidelines",
    "Hermes SafeGuard is active. Direct users to slash commands for mode switches and operator actions.",
    position="after_memory",
)
```

### Hook Registration
```python
ctx.register_hook("pre_tool_call", on_pre_tool_call)
ctx.register_hook("post_tool_call", on_post_tool_call)
```
- `pre_tool_call`: Receives tool name and arguments. Raising an exception halts execution (fails closed).
- `post_tool_call`: Receives tool name and execution result for audit logging.

### Secret Handling
- Passphrase passed via environment variable `SAFEGUARD_PASSPHRASE`.
- Private keys decrypted in memory only after simulation and policy pass; never written unencrypted or logged.

---

## 4. Validation & Quality Checklist
- Run `hermes plugins validate . --install-deps` before release.
- Avoid importing private Hermes modules; rely solely on public `ctx` APIs.
- Fail closed: any revert, simulation failure, or RPC timeout must abort the transaction.

---

## 5. Simulation Architecture (Anvil Fork)

SafeGuardPolicy.sol is **not** deployed to public chains. It runs locally.

### How it protects real transactions on live chains:
1. On plugin init, a **persistent Anvil daemon** forks the target chain (ETH mainnet, Base, etc.) via `--fork-url`.
2. SafeGuardPolicy.sol is deployed to this local fork once at startup.
3. When the agent submits a transaction, the `pre_tool_call` hook:
   - Calls `checkTransaction()` on the local fork via `eth_call` (zero gas, instant).
   - Simulates the actual transaction payload against live chain state (Anvil mirrors it).
4. If policy passes and simulation succeeds, the plugin signs the **real** transaction and sends it to the **real** RPC endpoint on the live chain.
5. If anything fails, the key is never decrypted. No transaction leaves the machine.

### Multi-chain support:
- `RPC_URL` environment variable determines which chain to fork.
- ETH mainnet: `https://eth.llamarpc.com` or user-provided Alchemy/Infura URL.
- Base mainnet: `https://mainnet.base.org` or user-provided URL.
- Plugin reads `chainId` from the transaction payload and validates it matches the forked chain.

### Secret Handling:
- `SAFEGUARD_PASSPHRASE` must be set as an environment variable at runtime.
- Never log the passphrase or raw private key material.
- Mask all error messages to avoid leaking key data, addresses, or calldata in stack traces.
- Private keys exist in memory only during the signing window (after policy pass, before broadcast).

---

## 6. Design Decisions

- **Daily limits**: Stateless. No cumulative tracking. Per-transaction value cap only. Keeps the Solidity contract pure and deterministic via `eth_call`.
- **No dummy data**: All tests and demos use real contract addresses and realistic calldata. Fork mainnet state for accurate simulation.
- **Anvil daemon**: Persistent process launched once on plugin init, reused for all guard calls. Eliminates per-transaction startup latency.