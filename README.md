# Hermes SafeGuard

[![Tests](https://img.shields.io/badge/tests-18%20passed-brightgreen.svg)]()
[![Scenarios](https://img.shields.io/badge/verification%20scenarios-12%2F12%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Foundry](https://img.shields.io/badge/foundry-Solidity%200.8.20-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-informational.svg)]()

> **Policy-Bounded Keystore & Transaction Security Middleware for Autonomous AI Agents**

Hermes SafeGuard provides defense-in-depth security middleware for autonomous on-chain agents (such as Nous Research's Hermes Agent). It ensures that agent private keys remain encrypted at rest and are only unlocked in memory when a transaction strictly complies with declarative policies and passes full EVM execution trace and state-diff simulation.

---

## Key Features

- **Defense-in-Depth Architecture**:
  - **Layer 1: Multi-Mode Policy Engine** (`strict`, `balanced`, `degen`) evaluating value caps, recipient allowlists, denylists, and calldata invariants.
  - **Layer 2: Stateless On-Chain Verification** (`SafeGuardPolicy.sol`) evaluated via `eth_call`.
  - **Layer 3: Execution Trace & State-Diff Simulation** (`debug_traceCall` via `callTracer` and `prestateTracer`) inspecting subcall frames, logs, and pre/post state changes.
- **Drain & Exploit Prevention**:
  - **Approval + transferFrom Drain Detection**: Blocks transactions granting approval and immediately executing `transferFrom` in the same batch or transaction.
  - **Sweeper Drain Detection**: Identifies and blocks multiple unauthorized transfers out across multiple tokens.
  - **Unexpected Asset Outflows**: Catches unexpected ERC-20/NFT transfers out during operations where outflows shouldn't occur (e.g. NFT mints).
  - **Unverified Contract Gating**: Flags or blocks `DELEGATECALL` and `CALL` to unverified or newly deployed contracts.
  - **Excess Balance Loss**: Ensures sender balance loss does not exceed the declared transaction value ($\Delta\text{ETH} \le \text{tx value}$).
  - **Recursive Multicall Inspection**: Unpacks nested `multicall(bytes[])` payloads to prevent smuggled drainer calls.
  - **Zero-Slippage Sandwich Defense**: Rejects DEX swaps vulnerable to MEV sandwiching.
- **Risk Scoring (`low` / `medium` / `high` / `critical`)**:
  - Categorizes all actions by risk.
  - In `degen` mode, medium-risk actions (e.g. interacting with unverified contracts) are permitted with a human-readable warning, while critical risks (actual drains and unexpected balance loss) are hard-blocked.
- **Zero External Dependencies**: Built entirely with Python standard library modules (`urllib`, `json`, `socket`, `unittest`, `dataclasses`).

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Autonomous AI Agent       |
                      |   (Hermes Agent Tool Call)  |
                      +--------------+--------------+
                                     |
                                     v
                 [ Hermes SafeGuard Security Middleware ]
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
+-----------------------+                         +--------------------------+
|  Layer 1: Policy      |                         |  Layer 2: Solidity       |
|  Engine Evaluation    |                         |  Policy Verification     |
|  (strict/balanced/    |                         |  SafeGuardPolicy.sol     |
|   degen rules)        |                         |  via eth_call            |
+----------+------------+                         +------------+-------------+
           |                                                   |
           +-------------------------+-------------------------+
                                     |
                                     v
                      +------------------------------+
                      |  Layer 3: Anvil Simulation   |
                      |  & Trace Inspection Layer    |
                      |  (debug_traceCall)           |
                      |  * callTracer                |
                      |  * prestateTracer            |
                      |  * Drain & Sweep Detection   |
                      |  * Risk Scoring Engine       |
                      +--------------+---------------+
                                     |
                    +----------------+----------------+
                    |                                 |
           [ Policy Passed ]                  [ Policy Failed ]
                    |                                 |
                    v                                 v
        +-----------------------+         +-----------------------+
        | Decrypt Key in Memory |         | Keystore Remains      |
        | Sign & Broadcast Tx   |         | Locked & Key Safe     |
        +-----------------------+         | Reject with Risk Log  |
                                          +-----------------------+
```

---

## Policy Engine Modes

Hermes SafeGuard supports three operational modes designed for different agent risk profiles:

| Mode | Max ETH / Tx | Unlimited Approvals | Slippage Defense | Unverified Contracts | Drains & Unexpected Outflows |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`strict`** | $0.5\text{ ETH}$ | Blocked | Blocked ($\text{minOut} > 0$) | Blocked | **Blocked** (`critical`) |
| **`balanced`** | $5.0\text{ ETH}$ | Blocked | Blocked ($\text{minOut} > 0$) | Blocked | **Blocked** (`critical`) |
| **`degen`** | $100.0\text{ ETH}$ | Allowed | Allowed | Allowed with Warning (`medium`) | **Blocked** (`critical`) |

### Declarative Policy Configuration (YAML)

Policies can be declared in YAML or passed as Python dictionaries:

```yaml
# policies/degen.yaml
mode: degen
max_eth_per_tx: 100000000000000000000  # 100 ETH
max_token_per_tx: 115792089237316195423570985008687907853269984665640564039457584007913129639935
allow_unlimited_approve: true
block_zero_slippage: false
recipient_allowlist: []
recipient_denylist:
  - "0x000000000000000000000000000000000000BAD1"
contract_allowlist:
  - "0x000000000000000000000000000000000000BEEF"
  - "0x000000000000000000000000000000000000C001"
```

---

## Project Structure

```
hermes-safeguard/
├── contracts/
│   ├── src/
│   │   └── SafeGuardPolicy.sol         # Core stateless on-chain policy verifier
│   ├── test/
│   │   └── SafeGuardPolicy.t.sol       # Foundry test suite
│   ├── out/
│   │   └── SafeGuardPolicy.sol/        # Pre-compiled contract artifact
│   └── foundry.toml                    # Foundry configuration
├── policies/
│   ├── strict.yaml                     # Conservative profile (0.5 ETH cap, strict allowlist)
│   ├── balanced.yaml                   # Moderate profile (5.0 ETH cap, balanced allowlist)
│   └── degen.yaml                      # High-activity profile (approvals allowed, drains blocked)
├── tests/
│   ├── test_policy_engine.py           # Unit tests for PolicyConfig and PolicyEngine
│   └── test_trace_inspection.py        # Unit tests for trace inspection & drain detection
├── policy_engine.py                    # Multi-mode policy engine & VerificationResult
├── verifier.py                         # Trace inspector, JSON-RPC client, test runner & CLI
├── CLAUDE.md                           # Architecture specifications & development guide
├── HERMES_SPEC.md                      # Hermes Agent plugin specification
└── README.md                           # Project documentation
```

---

## Quickstart & Usage

### 1. Python API

```python
from policy_engine import PolicyConfig
from verifier import verify_transaction

# Verify a transaction under the balanced policy profile
result = verify_transaction(
    to_address="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    value_wei=100_000_000_000_000_000,  # 0.1 ETH
    data_hex="0x...",
    config=PolicyConfig.balanced(recipient_allowlist=["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]),
)

if result.allowed:
    print(f"Transaction verified! Risk: {result.risk_score}")
    if result.warning:
        print(f"Warning: {result.warning}")
else:
    print(f"Transaction rejected: {result.reason} (Risk: {result.risk_score})")
```

The returned `VerificationResult` provides backward-compatible unpacking:
```python
# Unpack as (allowed, reason)
allowed, reason = result

# Unpack as (allowed, reason, risk_score)
allowed, reason, risk = result

# Or access attributes directly
print(result.allowed, result.reason, result.risk_score, result.warning)
```

---

## Running Tests

### 1. Verification Scenarios Runner

Runs all 12 test scenarios matching `SafeGuardPolicy.t.sol`, multi-mode evaluations, and expanded simulation checks (includes built-in fallback mock RPC when no local node is running):

```bash
python3 verifier.py --test
```

**Output:**
```text
--- Running SafeGuard Policy Verification Scenarios ---
[PASS] Scenario 1 (Safe transfer): allowed=True
[PASS] Scenario 2 (High ETH value): allowed=False, reason='SG: value exceeds max per tx'
[PASS] Scenario 3 (Unlimited ERC-20 approve): allowed=False, reason='SG: unbounded approve blocked'
[PASS] Scenario 4 (Smuggled multicall drain): allowed=False, reason='SG: selector blocked'
[PASS] Scenario 5 (Zero-slippage DEX swap): allowed=False, reason='SG: zero slippage swap blocked'
[PASS] Scenario 6 (Trace inspection DELEGATECALL / balance drain): allowed=False, reason='Trace inspection: sender balance loss exceeds transaction value'

--- Running Multi-Mode Policy Engine Scenarios (strict, balanced, degen) ---
[PASS] Scenario 7a (High ETH value): blocked in strict, allowed in degen
[PASS] Scenario 7b (Unlimited ERC-20 approve): blocked in strict & balanced, allowed in degen
[PASS] Scenario 7c.1 (Smuggled multicall drain in degen mode): properly blocked
[PASS] Scenario 7c.2 (Trace balance drain in degen mode): properly blocked
[PASS] Scenario 7c.3 (Denylisted recipient in degen mode): properly blocked
[PASS] Scenario 7c.4 (Unverified contract in degen mode): properly blocked
[PASS] Scenario 7d (Config loaded from YAML): allowed=True

--- Running Simulation & Trace Inspection Expanded Scenarios ---
[PASS] Scenario 8a (Legitimate OpenSea Seaport NFT mint): allowed=True, risk_score='low'
[PASS] Scenario 8b (Legitimate general NFT mint in degen): allowed=True, risk_score='low'
[PASS] Scenario 9 (Approval + transferFrom drain fails in degen): allowed=False, risk_score='critical'
[PASS] Scenario 10a (Normal swap in balanced mode): allowed=True, risk_score='low'
[PASS] Scenario 10b (Normal swap in degen mode): allowed=True, risk_score='low'
[PASS] Scenario 11 (Unexpected token/NFT transfer out fails in degen): allowed=False, risk_score='critical'
[PASS] Scenario 12 (Multiple transfers out sweeper drain fails): allowed=False, risk_score='critical'

[SUCCESS] All policy verification test scenarios passed successfully!
```

### 2. Comprehensive Unit Test Suite

```bash
python3 -m unittest discover tests -v
```

All 18 unit tests cover policy mode transitions, YAML roundtrips, invariant enforcement, trace inspection, and edge cases.

---

## Security Philosophy

1. **Fail Closed**: Any network failure, RPC error, simulation revert, or unhandled exception results in an immediate transaction rejection.
2. **Ephemeral Decryption**: The keystore is decrypted in RAM only after pre-flight approval and wiped immediately after signing.
3. **Never Trust Calldata Alone**: An agent can be prompt-injected or fooled by complex proxy contracts; simulation via execution trace inspection is mandatory.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
