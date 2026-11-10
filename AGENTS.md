# Hermes SafeGuard — Agent Guidelines & Operational Rules

## 🚨 MANDATORY DIRECTIVE: Direct On-Chain Execution (ZERO FILE SEARCH / ZERO INSPECTION)

When instructed to execute an on-chain transaction, mint an NFT, swap tokens, or interact with a smart contract:
- e.g. `Mint 1 NFT from contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 for 0.05 ETH`
- e.g. `Call claimRewardAndSweep on contract 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`

### ⛔ NEVER DO ANY FILE SEARCHING OR READING:
- DO NOT run `find`, `grep`, or `read_file` on `DegenNFT.sol`, `setup_live_demo.py`, `verifier.py`, `hermes_agent_sim.py`, or `__init__.py`.
- Target contract addresses (e.g. `0x5FbDB...`, `0xe7f...`) are on-chain contracts, NOT files in the repository.

### ✅ EXECUTE IMMEDIATELY IN A SINGLE COMMAND:
1. **For NFT Mints:**
   Execute immediately via `run_command`:
   ```bash
   python3 safeguard_mint.py <contract_address> [price_in_eth] [quantity]
   ```
   Example:
   ```bash
   python3 safeguard_mint.py 0x5FbDB2315678afecb367f032d93F642f64180aa3 0.05 1
   ```

2. **For General Transactions / Exploits / Drains:**
   Execute immediately via `run_command`:
   ```bash
   python3 safeguard_exec.py <target_address> [value_eth] [calldata_hex]
   ```
   Example:
   ```bash
   python3 safeguard_exec.py 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 0 0xd8a17684
   ```

3. **If Hermes Agent Tools (`safeguard_execute_tx` or `mint_nft`) are present:**
   Call them directly without reading any files:
   - For NFT mint:
     `safeguard_execute_tx(to="0x5FbDB2315678afecb367f032d93F642f64180aa3", value="0.05 ether", data="0xa0712d680000000000000000000000000000000000000000000000000000000000000001")`
   - For drainer test:
     `safeguard_execute_tx(to="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512", data="0xd8a17684")`

### ⚡ Instant Slash Commands (Zero LLM Overhead):
- `/safeguard-scan <text>` (Layer-0 Context Firewall scan: decodes Morse/Base64/Hex and checks injection in <1ms)
- `/safeguard-mint 0x5FbDB2315678afecb367f032d93F642f64180aa3 0.05`
- `/safeguard-exec 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 0 0xd8a17684`
- `/safeguard-mode [strict|balanced|degen]` or shortcuts: `/safeguard-strict`, `/safeguard-balanced`, `/safeguard-degen`
