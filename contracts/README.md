# Hermes SafeGuard - Smart Contracts

Foundry project containing the stateless on-chain policy verification contracts for Hermes SafeGuard.

## Contracts

- **`src/SafeGuardPolicy.sol`**:
  Stateless Solidity verifier contract evaluated via `eth_call`.
  - Enforces recipient allowlist / target gating.
  - Enforces native asset value cap per transaction ($\le \text{maxValuePerTx}$).
  - Blocks dangerous function selectors (e.g. `transferFrom` directly initiated or unbounded `approve`).
- **`test/SafeGuardPolicy.t.sol`**:
  Comprehensive Foundry unit and fuzz tests verifying policy evaluation under authorized and adversarial transactions.

## Build & Test with Foundry

```shell
# Build contracts
forge build

# Run Foundry tests
forge test

# Gas snapshot
forge snapshot
```

The compiled artifact is cached at `contracts/out/SafeGuardPolicy.sol/SafeGuardPolicy.json` for use by `verifier.py`.

## Solidity Bytecode Reproducibility & Build Settings

To independently reproduce and verify the deployed bytecode for `SafeGuardPolicy`:

- **Solidity Compiler (`solc`) Version:** `0.8.38+commit.1835d247`
- **EVM Target Version:** `osaka`
- **Optimizer:** `enabled: false` (`runs: 200`)
- **Language / Input:** Solidity `^0.8.20`
- **Source File:** `contracts/src/SafeGuardPolicy.sol`
- **Output Artifact:** `contracts/out/SafeGuardPolicy.sol/SafeGuardPolicy.json`

### CI Build & Verification Command

```shell
cd contracts
forge build --extra-output-files metadata abi bytecode
```

Or using standalone `solc`:

```shell
solc --evm-version osaka --bin --abi contracts/src/SafeGuardPolicy.sol -o contracts/out/
```

