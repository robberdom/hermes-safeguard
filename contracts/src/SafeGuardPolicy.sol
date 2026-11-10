// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SafeGuardPolicy
/// @notice Stateless transaction policy verifier. Evaluated via eth_call — never deployed onchain for state.
/// @dev Reverts with a descriptive message on any policy violation. Returns silently on success.
contract SafeGuardPolicy {
    uint256 public immutable maxValuePerTx;
    mapping(address => bool) public whitelisted;
    mapping(bytes4 => bool) public blockedSelectors;

    /// @dev Function selectors
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;
    bytes4 private constant MULTICALL_SELECTOR = 0xac9650d8;
    bytes4 private constant V2_SWAP_SELECTOR = 0x38ed1739;
    bytes4 private constant V2_SWAP_EXACT_ETH_FOR_TOKENS = 0x7ff36ab5;
    bytes4 private constant V2_SWAP_EXACT_TOKENS_FOR_ETH = 0x18cbafe5;
    bytes4 private constant V3_SWAP_SELECTOR = 0x414bf389;
    bytes4 private constant SET_APPROVAL_FOR_ALL_SELECTOR = 0xa22cb465;
    bytes4 private constant PERMIT2_APPROVE_SELECTOR = 0x87517c45;
    bytes4 private constant ERC20_TRANSFER_SELECTOR = 0xa9059cbb;

    /// @param _maxValuePerTx Maximum native asset (wei) allowed per transaction.
    /// @param _whitelist Array of allowed target addresses.
    /// @param _blocked Array of function selectors to restrict.
    constructor(
        uint256 _maxValuePerTx,
        address[] memory _whitelist,
        bytes4[] memory _blocked
    ) {
        maxValuePerTx = _maxValuePerTx;
        for (uint256 i = 0; i < _whitelist.length; ++i) {
            whitelisted[_whitelist[i]] = true;
        }
        for (uint256 i = 0; i < _blocked.length; ++i) {
            blockedSelectors[_blocked[i]] = true;
        }
    }

    /// @notice Verify a transaction against all policy rules.
    /// @param target Destination address.
    /// @param value Native asset value in wei.
    /// @param data ABI-encoded calldata.
    function checkTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external view {
        // 1. Value cap
        require(value <= maxValuePerTx, "SG: value exceeds max per tx");

        // 2. Target whitelist
        require(whitelisted[target], "SG: target not whitelisted");

        // 3. Selector restrictions (only when calldata is present)
        if (data.length >= 4) {
            bytes4 sel = bytes4(data[:4]);

            require(!blockedSelectors[sel], "SG: selector blocked");

            // 3a. Block unbounded ERC20 approvals: approve(spender, type(uint256).max)
            if (sel == APPROVE_SELECTOR) {
                require(data.length >= 68, "SG: malformed approve calldata");
                uint256 amount = abi.decode(data[36:68], (uint256));
                require(amount != type(uint256).max, "SG: unbounded approve blocked");
            }

            // 3b. Recursive Multicall Unpacking: multicall(bytes[])
            if (sel == MULTICALL_SELECTOR) {
                require(data.length >= 36, "SG: malformed multicall calldata");
                bytes[] memory calls = abi.decode(data[4:], (bytes[]));
                for (uint256 i = 0; i < calls.length; ++i) {
                    this.checkTransaction(target, 0, calls[i]);
                }
            }

            // 3c. Zero-Slippage Swap Protection: Uniswap V2 and V3
            if (sel == V2_SWAP_SELECTOR) {
                require(data.length >= 68, "SG: malformed swap calldata");
                uint256 amountOutMin = abi.decode(data[36:68], (uint256));
                require(amountOutMin > 0, "SG: zero slippage swap blocked");
            }
            if (sel == V2_SWAP_EXACT_ETH_FOR_TOKENS) {
                require(data.length >= 36, "SG: malformed swap calldata");
                uint256 amountOutMin = abi.decode(data[4:36], (uint256));
                require(amountOutMin > 0, "SG: zero slippage swap blocked");
            }
            if (sel == V2_SWAP_EXACT_TOKENS_FOR_ETH) {
                require(data.length >= 68, "SG: malformed swap calldata");
                uint256 amountOutMin = abi.decode(data[36:68], (uint256));
                require(amountOutMin > 0, "SG: zero slippage swap blocked");
            }
            if (sel == V3_SWAP_SELECTOR) {
                require(data.length >= 228, "SG: malformed swap calldata");
                uint256 amountOutMin = abi.decode(data[196:228], (uint256));
                require(amountOutMin > 0, "SG: zero slippage swap blocked");
            }

            // 3d. Modern Drainer & ERC20 Selectors
            if (sel == ERC20_TRANSFER_SELECTOR) {
                require(data.length >= 68, "SG: malformed transfer calldata");
                uint256 amount = abi.decode(data[36:68], (uint256));
                require(amount <= maxValuePerTx, "SG: token transfer amount exceeds token cap");
            }
            if (sel == SET_APPROVAL_FOR_ALL_SELECTOR) {
                require(data.length >= 68, "SG: malformed approval calldata");
                bool approved = abi.decode(data[36:68], (bool));
                require(!approved, "SG: setApprovalForAll blocked");
            }
            if (sel == PERMIT2_APPROVE_SELECTOR) {
                require(data.length >= 100, "SG: malformed permit2 calldata");
                uint160 amount = abi.decode(data[68:100], (uint160));
                require(amount <= maxValuePerTx, "SG: permit2 amount exceeds cap");
            }
        }
    }
}

