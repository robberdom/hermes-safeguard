# Hermes SafeGuard — Architecture & Developer Guide (CLAUDE.md)

**Hermes SafeGuard** is a policy-bounded keystore and defense-in-depth transaction security middleware for autonomous on-chain AI agents (specifically Nous Research's Hermes Agent). It intercepts agent tool calls and financial actions to ensure agent private keys remain encrypted at rest and are only unlocked in memory when a proposed transaction passes declarative policy rules, injection screening, memory integrity checks, and EVM execution trace and state-diff simulation.

---

## 1. Project Overview & Current State

Hermes SafeGuard has evolved from a simple static policy verifier into a multi-layered security engine implemented entirely in standard library Python (zero external Python runtime dependencies) paired with a stateless Solidity verifier (`contracts/src/SafeGuardPolicy.sol`) for on-chain execution guarantees.

### Key Capabilities
- **Multi-Mode Policy Engine**: Three operational modes (`strict`, `balanced`, `degen`) balancing autonomous agility with hard drain protection.
- **Defense-in-Depth Pipeline**: Pre-tool-call interception, prompt/indirect injection detection, persistent memory integrity checks, threat feed blocklisting, Solidity `eth_call` verification, and EVM trace simulation via `debug_traceCall`.
- **Ephemeral Keystore Decryption**: Private keys are decrypted in RAM only after all pre-flight simulations and policy gates pass; keys are wiped immediately post-broadcast. Execution fails closed on any error, RPC timeout, or revert.

---

## 2. Architecture & Transaction Pipeline

SafeGuard operates as middleware sitting between the autonomous agent and the live blockchain RPC:

```
                      +-----------------------------+
                      |   Autonomous AI Agent       |
                      |   (Hermes Agent Tool Call)  |
                      +--------------+--------------+
                                     |
                                     v
                  [ Hermes SafeGuard Security Middleware ]
                                     |
    +--------------------------------+--------------------------------+
    |                                                                 |
    v                                                                 v
+-------------------------------+                 +-------------------------------+
| Layer 0: Context & Memory     |                 | Layer 1: Threat Feed          |
| * Untrusted Context Scanner   |                 | * Local blocklist.json        |
| * Obfuscation Decoders        |                 | * Malicious contracts & EOAs  |
| * New Recipient Detection     |                 | * Blocked attack selectors    |
| * Address Memory Store        |                 | * Hard block in ALL modes     |
+---------------+---------------+                 +---------------+---------------+
                |                                                 |
                +------------------------+------------------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 2: Policy Engine Rules  |
                         | (strict / balanced / degen)   |
                         | * Value limits & Approvals    |
                         | * Multicall recursive inspect |
                         | * Zero-slippage swap gating   |
                         | * Contract & Recipient lists  |
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 3: Solidity Policy      |
                         | SafeGuardPolicy.sol via       |
                         | eth_call (stateless check)    |
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 4: EVM Trace Simulation |
                         | debug_traceCall on Anvil/RPC  |
                         | * callTracer & prestateTracer |
                         | * Excess sender balance loss  |
                         | * Approval + transferFrom     |
                         | * Sweeper multi-transfers out |
                         | * Unexpected NFT/token leaks  |
                         +---------------+---------------+
                                         |
                         +---------------+---------------+
                         |                               |
                [ Check Passed ]              [ Risk Gate Raised ]
                         |                               |
                         v                               v
             +-----------------------+       +-----------------------+
             | Decrypt Key in RAM    |       | Requires Confirmation |
             | Sign & Broadcast Tx   |       | or Hard Block         |
             +-----------------------+       | Keystore Stays Locked |
                                             +-----------------------+
```

### Where Policy Checks Run & How Simulation Works
1. **Python Pre-Flight Engine (`policy_engine.py`)**: Runs synchronously before any signing operation. Parses transaction parameters, scans the recent LLM context window for injection payloads, checks recipient novelty against `AddressMemoryStore`, and verifies parameters against the active `PolicyConfig`.
2. **Stateless On-Chain Policy (`contracts/src/SafeGuardPolicy.sol`)**: Executed via an `eth_call` query. Being stateless, it computes deterministically without modifying storage or incurring gas costs, verifying value bounds, allowed target addresses, and blocked selectors.
3. **Execution Trace & State-Diff Simulation (`verifier.py`)**:
   - Executes `debug_traceCall` on an Anvil local fork or target node using both `callTracer` (to inspect all internal calls, delegates, and call trees) and `prestateTracer` (to capture sender account balances before and after execution).
   - In offline test environments, a built-in lightweight fallback RPC server simulates trace outputs.
   - Trace inspector computes exact net balance reduction: $\Delta\text{ETH} = \text{balance}_{\text{pre}} - \text{balance}_{\text{post}}$. If $\Delta\text{ETH} > \text{tx value}$, it is flagged as an unexpected balance loss / drain.
   - Scans internal trace calls for nested drain patterns: approval granted followed by `transferFrom` within the same call frame, sweeper transfers to external addresses, or unverified `DELEGATECALL` invocations.

---

## 3. Policy Engine Modes

SafeGuard provides three distinct operational profiles:

| Dimension | `strict` | `balanced` (Default) | `degen` |
| :--- | :--- | :--- | :--- |
| **Primary Use Case** | Cold treasuries, high-security transfers | Everyday DeFi swaps & routine operations | NFT mints, high-frequency swaps, bot trading |
| **Max Native ETH / Tx** | $0.5\text{ ETH}$ | $5.0\text{ ETH}$ | $100.0\text{ ETH}$ |
| **Max Token Amount / Tx** | $0.5$ token units | $50.0$ token units | $\text{type}(\text{uint256}).\text{max}$ |
| **Unlimited Approvals** | Blocked | Blocked | **Allowed** |
| **Zero-Slippage Swaps** | Blocked | Blocked | Allowed for low value; requires confirmation if $\ge 1.0\text{ ETH}$ |
| **Unverified Contracts** | Blocked | Blocked | Allowed with warning; requires confirmation if high-risk |
| **New Recipients** | Requires confirmation | Allowed with warning (`MEDIUM` risk) | Allowed with warning (`MEDIUM` risk) |
| **Prompt Injections** | Hard-blocked (`CRITICAL` risk) | Requires confirmation (`HIGH` risk) | Requires confirmation (`HIGH` risk) |
| **Trace Balance Loss** | **Hard-blocked** | **Hard-blocked** | **Hard-blocked** |
| **Blocklist Targets** | **Hard-blocked** | **Hard-blocked** | **Hard-blocked** |

---

## 4. Deep Dive: Degen Mode

### Why Degen Mode Exists
Autonomous Web3 agents interacting with NFT mints, decentralized exchanges, or newly launched contracts frequently fail when subjected to traditional strict enterprise policies:
- NFT minting contracts are often newly deployed and unverified on block explorers at launch.
- DEX aggregators and NFT protocols require unlimited token approvals (`type(uint256).max` or `setApprovalForAll`) to avoid constant repeat approval transactions.
- Fast-paced on-chain environments require transactions up to 10–100 ETH without manual whitelisting.

A naive security system either breaks the agent's functionality completely or forces the user to disable security entirely. **Degen mode solves this dilemma**: it grants autonomy at the permission boundary while enforcing ironclad invariants at the execution simulation boundary.

### How Degen Mode Works
1. **Permissive Boundaries**:
   - Permits unlimited ERC-20 `approve(spender, type(uint256).max)` and ERC-721/1155 `setApprovalForAll(operator, true)`.
   - Permits high-value transactions up to $100.0\text{ ETH}$.
   - Permits NFT mint function selectors (`mint(uint256)`, `mintTo(...)`, SeaDrop, Seaport 1.5/1.6).
   - Allows interactions with contracts not explicitly listed in `contract_allowlist`.
2. **Non-Negotiable Invariants (Always Hard-Blocked)**:
   - **Threat Feed Matches**: Any interaction with addresses or selectors on `blocklist.json` is hard-blocked with `CRITICAL` risk. Confirmation cannot bypass this.
   - **Unexpected Balance Outflows**: If simulation shows the agent's wallet loses more ETH than declared in the transaction value ($\Delta\text{ETH} > \text{tx value}$), it is immediately rejected.
   - **Batch & Sweeper Drains**: Approval + immediate `transferFrom` in a single transaction and multi-token sweeps are hard-blocked.
   - **Unexpected Token/NFT Leaks**: If an NFT mint transaction causes tokens or NFTs to leave the agent's wallet, it is flagged as an exploit drain.
   - **Smuggled Multicalls**: Blocked selectors hidden within `multicall(bytes[])` payloads are unpacked and blocked.
3. **Elevated Confirmation Path**:
   - For situations that are suspicious but potentially legitimate (e.g., zero-slippage swap on $\ge 1.0\text{ ETH}$, or high-value action following an untrusted context message), Degen mode does **not** execute silently: it raises the risk score to `HIGH`, sets `requires_confirmation=True`, and issues a detailed human-readable confirmation request.

---

## 5. Main Protections & Defense Mechanisms

### 1. Amount Limits & Value Caps
Enforces strict maximum native ETH (`max_eth_per_tx`) and token transfer values. Any payload requesting transfer, swap, or value transfer above the configured cap is rejected or diverted to confirmation.

### 2. Unlimited Approve Blocking
Detects function selector `0x095ea7b3` (`approve(address,uint256)`) where the amount exceeds safe thresholds or equals $2^{256}-1$, as well as `0xa22cb465` (`setApprovalForAll(address,bool)`) and Permit2 `0x87517c45`. In `strict` and `balanced` modes, these are blocked. In `degen` mode, they are permitted only if subsequent simulation proves no immediate drain occurs.

### 3. Multicall & Selector Blocking
Detects dangerous calldata selectors (`0x23b872dd` `transferFrom`, `0xbaa2abde` sweepers, etc.). Inspects `multicall(bytes[])` (`0xac9650d8`) by recursively decoding nested calldata frames to prevent attackers from smuggling blocked selectors inside batched transactions.

### 4. Zero-Slippage Detection
Detects DEX swaps (Uniswap V2/V3, Universal Router, SushiSwap) where `amountOutMin == 0` or minimum output is set to zero. This protects against predatory MEV sandwich attacks. In `strict` and `balanced` modes, zero-slippage swaps are blocked. In `degen` mode, swaps $\ge 1.0\text{ ETH}$ with zero slippage require human confirmation.

### 5. Simulation & Trace Inspection for Unexpected Balance Loss
Executes pre-flight trace simulation. Analyzes pre/post state balance differences and internal execution calls:
- Blocks if $\text{ETH Loss} > \text{Declared Value}$.
- Blocks if an ERC-20 / ERC-721 token outflow occurs during non-outflow operations (e.g. NFT minting).
- Blocks sweeper patterns (multiple asset transfers out in a single transaction).
- Blocks unverified `DELEGATECALL` operations.

### 6. Prompt & Indirect Injection Signal Detection
Analyzes context messages passed to tool invocations (`check_pre_tool_call`):
- **Context Trust Tagging**: Distinguishes `trusted` context (system instructions, verified user directives) from `untrusted` context (scraped web pages, tweets/X posts, tool results, emails).
- **Obfuscation Decoders**: Automatically parses and decodes Morse code, Base64, and Hex encodings hiding malicious override payloads.
- **Financial Intent Pattern Recognition**: Flags prompt injection patterns (`override_and_financial_drain`, approval escalation, sweeper transfers, wallet modification).
- Mode-specific handling: `strict` hard-blocks financial actions; `balanced` and `degen` require human confirmation.

### 7. New-Recipient Checks & Poisoned Memory Defense
Defends against attacks attempting to rewrite agent internal memory with attacker-controlled addresses (AAP-001):
- Automatically extracts destination/recipient/spender addresses across native transfers, ERC-20, NFT mints, and Permit2 calls.
- Compares against `AddressMemoryStore` (persisted at `~/.hermes/approved_addresses.json` or custom path).
- In `strict` mode: any unapproved recipient requires explicit human confirmation (`requires_confirmation=True`).
- In `balanced` and `degen` modes: flags novelty (`is_new_recipient=True`), raises risk score to `MEDIUM`, and hard-blocks if combined with prompt injection or balance drain signals.
- Pre-approval tools: `safeguard_approve_address`, `safeguard_list_approved_addresses`, `safeguard_revoke_address`.

### 8. Threat Feed & Security Blocklist (`blocklist.json`)
Maintains a curated database of verified malicious contracts (Inferno Drainer, Fake Permit2 Router, Angel Drainer), phishing EOAs, dangerous calldata selectors, and Agent Attack Patterns (`AAP-001` through `AAP-006`):
- **Universal Hard-Block**: Any transaction targeting a blocklist address or using a blocked selector is hard-blocked across **all modes** with `CRITICAL` risk.
- **No Confirmation Bypass**: Even manual human confirmation (`confirmed=True`) cannot bypass a blocklist entry.
- **Search Tool**: `safeguard_search_threat_reports(query, limit)` allows querying threat intelligence.

### 9. Token Tax & Fee-on-Transfer Protection (Honeypot Defense)
Protects against predatory meme coins, honeypots, and fee-on-transfer tokens where extortionate sell taxes destroy portfolio value:
- **Trace Fee Analysis**: Inspects internal ERC-20 `transfer` and `transferFrom` calls during pre-flight DEX swap or transfer simulation, measuring tokens diverted to dev, fee, or burn wallets versus tokens delivered to the liquidity pool or destination.
- **Extortionate Tax ($\ge 50\%$ up to $99\%+$)**: **Hard-blocked across ALL modes (including `degen` mode)** with `CRITICAL` risk. Execution aborts immediately to protect user capital from total wipeout.
- **High Tax ($\ge 25\%$ up to $50\%$)**: 
  - In `degen` and `balanced` modes: Permits the transaction with a prominent warning (`Warning: High token tax detected (XX.X% tax exceeds 25% threshold)`) and elevated `HIGH` risk score.
  - In `strict` mode: Hard-blocks high tax transfers.
- **Multi-Chain Routers Recognized**: `KNOWN_VERIFIED_PROTOCOLS` pre-verifies Ethereum Mainnet (Uniswap V2, V3, SwapRouter02, Universal Router), Base (Uniswap SwapRouter02, Universal Router, Aerodrome V2 & Slipstream), and Robinhood (L1 Gateway Router `0x6a2E...` and Arbitrum Router).

---

## 6. How to Configure Modes & Allowlists

### 1. YAML Configuration Files
Policies can be loaded from YAML files in `policies/`:

```yaml
# policies/balanced.yaml
mode: balanced
max_eth_per_tx: 5000000000000000000  # 5.0 ETH
max_token_per_tx: 50000000000000000000  # 50 tokens
allow_unlimited_approve: false
require_simulation: true
block_zero_slippage: true
recipient_allowlist: []
recipient_denylist:
  - "0x000000000000000000000000000000000000BAD1"
contract_allowlist: []
pre_approved_addresses:
  - address: "0x1111111111111111111111111111111111111111"
    label: "Treasury Wallet"
```

### 2. Python API Configuration
Instantiate pre-tuned presets or customize:

```python
from policy_engine import PolicyConfig, PolicyMode
from verifier import verify_transaction

# Built-in presets
config_strict = PolicyConfig.strict()
config_balanced = PolicyConfig.balanced()
config_degen = PolicyConfig.degen()

# Custom configuration
custom_config = PolicyConfig(
    mode=PolicyMode.BALANCED,
    max_eth_per_tx=2 * 10**18,  # 2.0 ETH
    allow_unlimited_approve=False,
    block_zero_slippage=True,
    recipient_allowlist=["0x2222222222222222222222222222222222222222"],
)

# Load from YAML file
config_from_yaml = PolicyConfig.from_yaml("policies/degen.yaml")
```

### 3. Environment Variables
- `SAFEGUARD_MODE`: Sets the default operational mode (`strict`, `balanced`, `degen`).
- `SAFEGUARD_POLICY_PATH`: Path to a declarative policy YAML file.
- `SAFEGUARD_RPC_URL`: JSON-RPC URL for local Anvil or upstream execution node (default: `http://127.0.0.1:8545`).
- `SAFEGUARD_PASSPHRASE`: Keystore decryption passphrase. Never logged.
- `SAFEGUARD_BLOCKLIST_PATH`: Custom path to `blocklist.json`.
- `SAFEGUARD_MEMORY_PATH`: Custom path to persistent address store JSON.

### 4. Address Pre-Approval via Tool API
```python
from policy_engine import safeguard_approve_address, safeguard_list_approved_addresses

# Pre-approve a trusted recipient or contract
safeguard_approve_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", label="Uniswap V2 Router")

# List currently approved addresses
approved = safeguard_list_approved_addresses()
```

---

## 7. Current Test Status & How to Run the Verifier

Hermes SafeGuard maintains a complete zero-dependency test suite covering contract invariants, policy engine logic, trace simulations, injection attacks, threat feeds, and memory integrity.

### Current Test Status
- **95 Unit Tests**: 100% passing (`Ran 95 tests in ~0.25s - OK`).
- **38 Verification Scenarios**: 100% passing across 18 scenario test suites (`verifier.py --test`).

### Running the Test Suites

#### 1. Run All Unit Tests
```bash
python3 -m unittest discover tests -v
```
Test suite breakdown:
- `tests/test_policy_engine.py`: Multi-mode rules, YAML loading, amount limits, unpack compatibility.
- `tests/test_trace_inspection.py`: Trace simulation, balance losses, sweeper drains, approval drains.
- `tests/test_prompt_injection.py`: Context trust tagging, Morse/Base64/Hex decoders, injection flags.
- `tests/test_threat_feed.py`: Blocklist parsing, malicious contract blocking, threat search tool.
- `tests/test_memory_integrity.py`: Persistent address store, new recipient gating, poisoned memory attacks.

#### 2. Run the Verification Scenarios Runner
```bash
python3 verifier.py --test
```
*Note*: If an active Anvil instance is not running on `127.0.0.1:8545`, `verifier.py` automatically spins up an in-process mock JSON-RPC fallback server to validate all 18 scenarios cleanly.

#### 3. CLI Transaction Verification
Verify an arbitrary transaction payload from the terminal:
```bash
# Verify a safe transaction in balanced mode
python3 verifier.py --to 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --value 0.1 --mode balanced

# Test rejection in strict mode for value exceeding cap
python3 verifier.py --to 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --value 1.0 --mode strict
```

---

## 8. Human Confirmation Workflow

When an action is flagged with `requires_confirmation=True`:
1. SafeGuard generates a unique `confirmation_id` (e.g., `conf_5eb5ac435442`) and registers the request in `ConfirmationStore`.
2. A structured summary (`confirmation_summary`) is generated detailing the target, value, action type, risk score, and reason.
3. The host application or chat adapter prompts the human operator.
4. The human confirms or rejects via `safeguard_confirm_action(confirmation_id, approved=True|False)`.
5. On confirmation, re-evaluating the transaction with `confirmation_id` unlocks execution.

```python
from policy_engine import safeguard_confirm_action
from verifier import verify_transaction

# Human approves pending action
safeguard_confirm_action(confirmation_id="conf_5eb5ac435442", approved=True)

# Transaction re-evaluation passes
result = verify_transaction(
    to_address="0x...",
    value_wei=10**18,
    data_hex="",
    confirmation_id="conf_5eb5ac435442"
)
assert result.allowed is True
```

---

## 9. Known Limitations & Next Priorities

### 1. Live Threat Feed Integration
- **Current State**: Static local `blocklist.json` with manual updates and agent query tool (`safeguard_search_threat_reports`).
- **Next Priority**: Background cron worker and webhook ingestion service synchronizing real-time malicious addresses and exploit reports directly from Web3 security APIs (SlowMist, ScamSniffer, PeckShield, Chainabuse) and live security alert monitoring.

### 2. Full Hermes Hook & Runtime Integration
- **Current State**: Core policy verification, hook simulation logic (`check_pre_tool_call`), and standalone CLI/Python APIs are fully tested.
- **Next Priority**: Package and publish the plugin complying with the Hermes plugin directory standard (`plugin.yaml`, `__init__.py` with `register(ctx)`), ensuring smooth validation via `hermes plugins validate . --install-deps` in upstream Hermes agent environments.

### 3. Messaging-Based Confirmation UI
- **Current State**: Programmatic `ConfirmationStore` and tool APIs (`safeguard_confirm_action`).
- **Next Priority**: Out-of-the-box chat adapters for Telegram, Discord, and Hermes web UI with interactive inline approval/rejection buttons, automated request expiration timers, and secure signature dispatching.

### 4. Agent Skill Scanner
- **Current State**: Runtime screening of prompt context messages and transaction calldata.
- **Next Priority**: Pre-execution static analysis tool that scans third-party agent skills and instruction files (`SKILL.md`, associated python scripts, prompt templates) for concealed prompt injections, hidden financial drains, or backdoor tools before skills are loaded into the agent runtime.

---

## 10. Repository File Map

```
hermes-safeguard/
├── blocklist.json              # Curated local threat feed (drainers, phishing, AAP patterns)
├── contracts/
│   ├── src/
│   │   └── SafeGuardPolicy.sol # Stateless on-chain Solidity policy verifier
│   └── test/
│       └── SafeGuardPolicy.t.sol # Foundry contract test suite
├── policies/
│   ├── strict.yaml             # Conservative policy profile (0.5 ETH cap)
│   ├── balanced.yaml           # Default operational profile (5.0 ETH cap)
│   └── degen.yaml              # High-interaction profile (100 ETH, approvals allowed)
├── tests/
│   ├── test_policy_engine.py   # Core policy logic, YAML loading, mode verification
│   ├── test_trace_inspection.py# EVM trace simulation, balance loss & drain tests
│   ├── test_prompt_injection.py# Prompt & indirect injection defense tests
│   ├── test_threat_feed.py     # Blocklist & threat search tests
│   └── test_memory_integrity.py# Persistent address store & new recipient tests
├── policy_engine.py            # Primary Python policy engine, data structures, stores
├── verifier.py                 # Simulation engine, trace inspector, test runner, CLI
├── CLAUDE.md                   # This developer & architecture guide
├── HERMES_SPEC.md              # Hermes Agent plugin specification reference
├── README.md                   # Public project documentation & quickstart
└── STEPS.md                    # Sprint tracking and development history
```

---

## 11. Developer Guidelines for Future AI & Human Sessions

- **Preserve Zero-Dependency Core**: The Python middleware (`policy_engine.py`, `verifier.py`) must remain pure Python standard library. Do not introduce dependencies on `web3.py`, `eth-account`, or third-party request libraries.
- **Always Fail Closed**: Any failure—unhandled exception, malformed calldata, unrecognized selector, RPC timeout, or simulation revert—must immediately yield `allowed=False` with keystores locked.
- **Never Log Secrets**: The decryption passphrase and decrypted private keys must never appear in logs, audit records, or exception messages.
- **Maintain Deterministic Unpacking**: `VerificationResult` supports backward-compatible unpacking as `(allowed, reason)`, `(allowed, reason, risk_score)`, or `(allowed, reason, risk_score, requires_confirmation)` to prevent breaking legacy callers.
- **Validate Before Committing**:
  ```bash
  python3 -m unittest discover tests -v
  python3 verifier.py --test
  ```
