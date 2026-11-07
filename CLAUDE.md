# Project: Hermes SafeGuard Plugin

Policy-bounded keystore and transaction security middleware for Nous Research's Hermes Agent.

---

## 1. Architecture

1. **`contracts/src/SafeGuardPolicy.sol`**:
   - Stateless Solidity policy verifier evaluated via `eth_call`.
   - `checkTransaction(address target, uint256 value, bytes calldata data)` verifies:
     - Target address whitelist.
     - Maximum native asset value per transaction (e.g., $\le 0.5$ ETH).
     - Blocked function selectors (e.g., unbounded ERC-20 `approve(address, type(uint256).max)`).

2. **`plugin.yaml`**:
   - Declares `provides_tools`: `safeguard_check_policy`, `safeguard_execute_tx`.
   - Declares `provides_hooks`: `pre_tool_call`, `post_tool_call`.
   - Declares `capabilities`: `tools.override`.

3. **`__init__.py`**:
   - Entrypoint `def register(ctx):`.
   - Registers tools (`safeguard_check_policy`, `safeguard_execute_tx`).
   - Launches a **persistent Anvil daemon** on plugin init (forks target chain via `RPC_URL`). Reuses this single process for all guard calls.
   - Deploys `SafeGuardPolicy.sol` to the local fork once at startup.
   - Hooks into `pre_tool_call` to intercept `eth_sendTransaction` or Web3 calls.
   - Runs `checkTransaction()` via `eth_call` on the local fork, then simulates the full transaction.
   - If policy passes: decrypts AES-GCM keystore in memory, signs, and sends to the **real** chain RPC.
   - If policy fails: key is never decrypted. Transaction is rejected. Audit log records the violation.
   - Fails closed on any policy violation, revert, RPC timeout, or chain mismatch.
   - `SAFEGUARD_PASSPHRASE` required as env var. Never logged. Error messages are masked to prevent key/calldata leaks.

---

## 2. Hero Demo (To Build After Core Product)

Build after completing the core contract, manifest, and plugin entrypoint:

1. **Scenario A (Authorized Action):**
   - The agent initiates an authorized swap within value and target limits.
   - SafeGuard runs pre-flight simulation, verifies policy, decrypts key, signs, and broadcasts transaction.
   - Agent receives valid transaction receipt.

2. **Scenario B (Prompt Injection Defense):**
   - Simulated adversarial prompt injection instructs the agent to drain funds or grant an unbounded approval (`approve(attacker, type(uint256).max)`).
   - SafeGuard intercepts payload in `pre_tool_call`, detects selector/value violation during policy check, and halts execution.
   - Keystore remains locked; private key is never decrypted.
   - Audit log records rejected payload and specific policy failure.

---

## 3. Step-by-Step Build Plan

- **Step 1: Policy Contract & Foundry Suite**
  - Implement `contracts/src/SafeGuardPolicy.sol`.
  - Write Foundry tests in `contracts/test/SafeGuardPolicy.t.sol` covering whitelist, value cap, and blocked selectors.
  - Compile contracts (`forge build`).

- **Step 2: Manifest & Keystore Management**
  - Create `plugin.yaml` complying with `HERMES_SPEC.md`.
  - Implement encrypted keystore loader in Python using AES-GCM and `SAFEGUARD_PASSPHRASE`.

- **Step 3: Verification & Signing Engine (`__init__.py`)**
  - Implement `register(ctx)` with tool and hook bindings.
  - Implement pre-flight simulation logic using `eth_call` against the local policy contract.
  - Wire signing pipeline: only sign when simulation and policy checks succeed.

- **Step 4: Plugin Validation & Unit Tests**
  - Run `hermes plugins validate . --install-deps`.
  - Add pytest suite covering tool handlers, hook interception, and fail-closed edge cases.

- **Step 5: Hero Demo Script**
  - Create `demo/hero_demo.py` showcasing Scenario A (success) and Scenario B (injection mitigation).

---

## 4. Strict Development Rules

- Consult `HERMES_SPEC.md` before altering `plugin.yaml` or `__init__.py`.
- Keep tool and hook names identical across `plugin.yaml`, `HERMES_SPEC.md`, and code.
- Import only public Hermes APIs permitted by `hermes plugins validate`.
- Keep Solidity verifiers stateless to ensure fast, deterministic `eth_call` validation.
- Fail closed: any error, policy breach, or RPC failure must reject execution immediately.
- Maintain concise code and minimal external dependencies.
