# Hermes SafeGuard — Build Steps & Sprint Plan

---

## 3-Day Sprint Roadmap

### Day 1: Contracts & Manifest

| Task | Deliverable |
|------|-------------|
| Implement `SafeGuardPolicy.sol` (stateless: whitelist, value cap, blocked selectors) | Compiled contract |
| Write Foundry tests covering every guard rule + fuzz tests | Passing `forge test` |
| Create `plugin.yaml` matching `HERMES_SPEC.md` exactly | Valid manifest |

### Day 2: Python Plugin Core

| Task | Deliverable |
|------|-------------|
| Implement AES-GCM keystore encryption/decryption module | `keystore.py` |
| Implement `__init__.py` with `register(ctx)` | Working plugin entrypoint |
| Wire persistent Anvil daemon (fork chain on init, reuse for all calls) | `anvil_manager.py` |
| Implement `pre_tool_call` hook: simulate → policy check → sign → send | Transaction pipeline |
| Implement `post_tool_call` hook: audit logging | Audit trail |
| Add pytest suite for tool handlers, hooks, fail-closed paths | Passing tests |

### Day 3: Integration, Demo & Polish

| Task | Deliverable |
|------|-------------|
| Run `hermes plugins validate . --install-deps` — fix any violations | Clean validation |
| Test against ETH mainnet fork | Verified on mainnet state |
| Test against Base mainnet fork | Verified on Base state |
| Build hero demo script (`demo/hero_demo.py`) | Working demo |
| Write `README.md` with setup instructions | Documentation |

---

## Step-by-Step Build Order

### Step 1: Policy Contract & Foundry Suite ✅ (Done)
- [x] `contracts/src/SafeGuardPolicy.sol` — stateless verifier.
- [x] `contracts/test/SafeGuardPolicy.t.sol` — whitelist, value cap, blocked selectors, unbounded approve, fuzz.
- [ ] Run `forge build` and `forge test` to confirm.

### Step 2: Manifest
- [ ] Create `plugin.yaml` at project root matching `HERMES_SPEC.md` §2.
- [ ] Tool names: `safeguard_check_policy`, `safeguard_execute_tx`.
- [ ] Hook names: `pre_tool_call`, `post_tool_call`.
- [ ] Capability: `tools.override`.

### Step 3: Keystore Module
- [ ] Implement `keystore.py`:
  - AES-GCM encryption and decryption.
  - Reads `SAFEGUARD_PASSPHRASE` from env var. Aborts if missing.
  - Key material exists in memory only during signing window.
  - Never logs passphrase, private key, or raw key bytes.
  - Error messages are masked — no key data, no calldata, no addresses in stack traces.
- [ ] Write `scripts/generate_keystore.py` to create an encrypted keystore from a private key.

### Step 4: Anvil Daemon Manager
- [ ] Implement `anvil_manager.py`:
  - On plugin init, launch a **single persistent Anvil process** forking the target chain.
  - `RPC_URL` env var determines fork target (ETH mainnet, Base, etc.).
  - Deploy `SafeGuardPolicy.sol` to the local fork once at startup.
  - Store the policy contract address and local Anvil RPC endpoint.
  - Reuse for all subsequent `eth_call` guard checks.
  - Health check: if Anvil dies, refuse all transactions (fail closed).

### Step 5: Plugin Entrypoint (`__init__.py`)
- [ ] `def register(ctx):` wires everything:
  - Start Anvil daemon → deploy policy contract.
  - Register `safeguard_check_policy` tool (dry-run policy check, no signing).
  - Register `safeguard_execute_tx` tool (full pipeline: simulate → check → sign → send).
  - Register `pre_tool_call` hook intercepting `eth_sendTransaction` / Web3 send tools.
  - Register `post_tool_call` hook for audit logging.

### Step 6: Transaction Pipeline (inside `pre_tool_call`)
- [ ] Extract `to`, `value`, `data`, `chainId` from the intercepted tool call.
- [ ] Validate `chainId` matches the forked chain.
- [ ] Call `SafeGuardPolicy.checkTransaction(to, value, data)` via `eth_call` on local Anvil fork.
- [ ] If revert → reject immediately. Key is never touched.
- [ ] If pass → simulate the full transaction via `eth_call` on the fork to check for reverts.
- [ ] If simulation succeeds → decrypt keystore → sign transaction → send to **real chain RPC**.
- [ ] If simulation fails → reject. Log the revert reason.

### Step 7: Testing
- [ ] Foundry tests: `forge test` (already written).
- [ ] Pytest suite:
  - Hook interception works for target tool names.
  - Policy violations halt execution before key decryption.
  - Valid transactions pass through and produce signed output.
  - Missing `SAFEGUARD_PASSPHRASE` aborts immediately.
  - Anvil daemon crash triggers fail-closed behavior.
- [ ] Fork tests against ETH mainnet (real Uniswap, USDC addresses).
- [ ] Fork tests against Base mainnet (real Base contract addresses).

### Step 8: Plugin Validation
- [ ] Run `hermes plugins validate . --install-deps`.
- [ ] Fix any public API import violations.
- [ ] Verify manifest ↔ code name consistency.

### Step 9: Hero Demo (After Core Product)
- [ ] Create `demo/hero_demo.py`:
  - **Scenario A (Authorized):** Agent swaps 0.1 ETH on Uniswap via a whitelisted router. SafeGuard passes. Transaction signs and executes.
  - **Scenario B (Prompt Injection):** Adversarial prompt tricks agent into calling `approve(attacker, type(uint256).max)`. SafeGuard intercepts in `pre_tool_call`, rejects, logs violation. Key never decrypted.
- [ ] Console output clearly shows pass/reject with policy reason.
- [ ] No dummy data. Real contract addresses, real calldata, forked mainnet state.

### Step 10: README & Submission
- [ ] Write `README.md`: what it does, setup instructions, env vars, how to run demo.
- [ ] Ensure `forge build`, `forge test`, `pytest`, and demo all run from a clean clone.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Daily spend limits | **Stateless — per-tx cap only** | Keeps Solidity pure. No storage writes, no DB, deterministic `eth_call`. |
| Simulation backend | **Persistent local Anvil daemon** | No external API keys. Fast. Fails closed if process dies. |
| Test data | **No dummy data** | Fork real mainnet/Base state. Use real contract addresses. |
| Multi-chain | **ETH mainnet + Base** | Configurable via `RPC_URL`. Validate `chainId` match. |
| Secret handling | **`SAFEGUARD_PASSPHRASE` env var** | Never logged. Error messages masked. Key in memory only during signing. |
| Contract deployment | **Local fork only** | Policy contract lives on Anvil. Real txs go to real chain after passing local checks. |

---

## Risk Register: What Could Make This Fail

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Hermes `ctx` API changes or is undocumented** | High | Pin `requires_hermes` version. Test against released Hermes. Read source if docs are thin. |
| **Anvil not installed on judge's machine** | High | Document Foundry install in README. Provide a fallback mode using raw `eth_call` to a public RPC without Anvil. |
| **RPC rate limits when forking mainnet** | Medium | Use free endpoints (LlamaRPC, Base public). Cache fork state. Anvil only fetches state on-demand. |
| **Gas estimation mismatch between fork and live** | Medium | Simulation uses fork state which mirrors live. Add gas buffer (e.g., 1.2x estimated). |
| **Multicall / proxy patterns bypass selector checks** | Medium | Document known limitation. Future: decode nested calls in multicall payloads. |
| **Nonce conflicts with concurrent agent actions** | Medium | Serialize signing through a single lock. Query nonce from live RPC at sign time. |
| **AES-GCM keystore implementation bug leaks key** | High | Use `pycryptodome` (audited). Unit test encrypt/decrypt round-trip. Never log decrypted output. |
| **Plugin not useful without existing `eth_sendTransaction` tool** | Medium | Provide `safeguard_execute_tx` as a standalone tool that doesn't depend on intercepting another tool. |
| **Scope creep into ERC-4337 / account abstraction** | Low | Stay out of scope. This is a signing gateway, not a smart account. |
| **Demo doesn't clearly show the value** | Medium | Hero demo must show both pass and reject in under 30 seconds with clear console output. |

---

## Environment & Dependencies

### Required
- Python >= 3.10
- Foundry (forge, anvil, cast)
- `pip`: `web3`, `eth-account`, `pycryptodome`
- Hermes Agent >= 0.22.0

### Environment Variables
- `RPC_URL` — Fork target RPC (ETH mainnet or Base mainnet).
- `SAFEGUARD_PASSPHRASE` — Keystore decryption passphrase. Required. Never logged.
- `SAFEGUARD_MAX_VALUE` — (Optional) Override max value per tx in wei. Default: 0.5 ETH.

