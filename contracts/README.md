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
