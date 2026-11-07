// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SafeGuardPolicy} from "../src/SafeGuardPolicy.sol";

contract SafeGuardPolicyTest is Test {
    SafeGuardPolicy public policy;

    address constant ALLOWED_TARGET = address(0xBEEF);
    address constant BLOCKED_TARGET = address(0xDEAD);
    uint256 constant MAX_VALUE = 0.5 ether;

    // approve(address,uint256) selector
    bytes4 constant APPROVE_SEL = 0x095ea7b3;
    // transferFrom(address,address,uint256) selector — used as a blocked selector
    bytes4 constant TRANSFER_FROM_SEL = 0x23b872dd;
    // multicall(bytes[]) selector
    bytes4 constant MULTICALL_SEL = 0xac9650d8;
    // Uniswap V2 swapExactTokensForTokens selector
    bytes4 constant V2_SWAP_SEL = 0x38ed1739;
    // Uniswap V3 exactInputSingle selector
    bytes4 constant V3_SWAP_SEL = 0x414bf389;
    // setApprovalForAll(address,bool) selector
    bytes4 constant SET_APPROVAL_FOR_ALL_SEL = 0xa22cb465;
    // Permit2 approve(address,address,uint160,uint48) selector
    bytes4 constant PERMIT2_APPROVE_SEL = 0x87517c45;

    function setUp() public {
        address[] memory whitelist = new address[](1);
        whitelist[0] = ALLOWED_TARGET;

        bytes4[] memory blocked = new bytes4[](1);
        blocked[0] = TRANSFER_FROM_SEL;

        policy = new SafeGuardPolicy(MAX_VALUE, whitelist, blocked);
    }

    // ----------------------------------------------------------------
    // Value cap tests
    // ----------------------------------------------------------------

    function test_allowsTxWithinValueCap() public view {
        policy.checkTransaction(ALLOWED_TARGET, 0.1 ether, "");
    }

    function test_allowsTxAtExactValueCap() public view {
        policy.checkTransaction(ALLOWED_TARGET, MAX_VALUE, "");
    }

    function test_revertsTxExceedingValueCap() public {
        vm.expectRevert("SG: value exceeds max per tx");
        policy.checkTransaction(ALLOWED_TARGET, MAX_VALUE + 1, "");
    }

    // ----------------------------------------------------------------
    // Whitelist tests
    // ----------------------------------------------------------------

    function test_allowsWhitelistedTarget() public view {
        policy.checkTransaction(ALLOWED_TARGET, 0, "");
    }

    function test_revertsNonWhitelistedTarget() public {
        vm.expectRevert("SG: target not whitelisted");
        policy.checkTransaction(BLOCKED_TARGET, 0, "");
    }

    // ----------------------------------------------------------------
    // Selector block tests
    // ----------------------------------------------------------------

    function test_revertsBlockedSelector() public {
        bytes memory data = abi.encodeWithSelector(
            TRANSFER_FROM_SEL,
            address(0x1),
            address(0x2),
            100
        );
        vm.expectRevert("SG: selector blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_allowsNonBlockedSelector() public view {
        // transfer(address,uint256) — not blocked
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x1),
            100
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    // ----------------------------------------------------------------
    // Unbounded approve tests
    // ----------------------------------------------------------------

    function test_revertsUnboundedApprove() public {
        bytes memory data = abi.encodeWithSelector(
            APPROVE_SEL,
            address(0x1),
            type(uint256).max
        );
        vm.expectRevert("SG: unbounded approve blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_allowsBoundedApprove() public view {
        bytes memory data = abi.encodeWithSelector(
            APPROVE_SEL,
            address(0x1),
            1000 ether
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    // ----------------------------------------------------------------
    // Edge cases
    // ----------------------------------------------------------------

    function test_allowsEmptyCalldata() public view {
        policy.checkTransaction(ALLOWED_TARGET, 0, "");
    }

    function test_allowsShortCalldata() public view {
        // Less than 4 bytes — no selector to check
        policy.checkTransaction(ALLOWED_TARGET, 0, hex"aabb");
    }

    function testReverts_malformedApprove() public {
        // Valid selector but insufficient calldata (only 4 bytes)
        bytes memory data = hex"095ea7b3";
        vm.expectRevert("SG: malformed approve calldata");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_revertsMalformedApproveCalldata() public {
    // approve selector + address but no amount (only 36 bytes)
    bytes memory data = abi.encodePacked(
        APPROVE_SEL,
        bytes32(uint256(uint160(address(0x1))))
    );
    vm.expectRevert("SG: malformed approve calldata");
    policy.checkTransaction(ALLOWED_TARGET, 0, data);
}

    // ----------------------------------------------------------------
    // Scenario 4: Smuggled drain hidden inside a multicall(bytes[]) batch (Blocked)
    // ----------------------------------------------------------------

    function test_scenario4_revertsSmuggledBlockedSelectorInMulticall() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x1),
            100
        );
        calls[1] = abi.encodeWithSelector(
            TRANSFER_FROM_SEL,
            address(0x1),
            address(0x2),
            100
        );

        bytes memory multicallData = abi.encodeWithSelector(MULTICALL_SEL, calls);
        vm.expectRevert("SG: selector blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, multicallData);
    }

    function test_scenario4_revertsSmuggledUnboundedApproveInMulticall() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x1),
            100
        );
        calls[1] = abi.encodeWithSelector(
            APPROVE_SEL,
            address(0x1),
            type(uint256).max
        );

        bytes memory multicallData = abi.encodeWithSelector(MULTICALL_SEL, calls);
        vm.expectRevert("SG: unbounded approve blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, multicallData);
    }

    function test_scenario4_revertsNestedSmuggledDrainInMulticall() public {
        bytes[] memory innerCalls = new bytes[](1);
        innerCalls[0] = abi.encodeWithSelector(
            TRANSFER_FROM_SEL,
            address(0x1),
            address(0x2),
            100
        );
        bytes memory nestedMulticall = abi.encodeWithSelector(MULTICALL_SEL, innerCalls);

        bytes[] memory outerCalls = new bytes[](1);
        outerCalls[0] = nestedMulticall;

        bytes memory multicallData = abi.encodeWithSelector(MULTICALL_SEL, outerCalls);
        vm.expectRevert("SG: selector blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, multicallData);
    }

    function test_scenario4_allowsSafeMulticall() public view {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x1),
            100
        );
        calls[1] = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x2),
            200
        );

        bytes memory multicallData = abi.encodeWithSelector(MULTICALL_SEL, calls);
        policy.checkTransaction(ALLOWED_TARGET, 0, multicallData);
    }

    function test_scenario4_revertsMalformedMulticall() public {
        bytes memory data = hex"ac9650d8";
        vm.expectRevert("SG: malformed multicall calldata");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    // ----------------------------------------------------------------
    // Scenario 5: Zero-slippage DEX swap (amountOutMin = 0) vulnerable to MEV sandwiching (Blocked)
    // ----------------------------------------------------------------

    function test_scenario5_revertsV2ZeroSlippageSwap() public {
        address[] memory path = new address[](2);
        path[0] = address(0x1);
        path[1] = address(0x2);

        bytes memory data = abi.encodeWithSelector(
            V2_SWAP_SEL,
            1 ether,
            0, // amountOutMin = 0
            path,
            address(this),
            block.timestamp + 100
        );
        vm.expectRevert("SG: zero slippage swap blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario5_allowsV2SwapWithSlippageProtection() public view {
        address[] memory path = new address[](2);
        path[0] = address(0x1);
        path[1] = address(0x2);

        bytes memory data = abi.encodeWithSelector(
            V2_SWAP_SEL,
            1 ether,
            0.9 ether,
            path,
            address(this),
            block.timestamp + 100
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario5_revertsV3ZeroSlippageSwap() public {
        bytes memory data = abi.encodeWithSelector(
            V3_SWAP_SEL,
            address(0x1),
            address(0x2),
            uint24(3000),
            address(this),
            block.timestamp + 100,
            1 ether,
            0, // amountOutMinimum = 0
            uint160(0)
        );
        vm.expectRevert("SG: zero slippage swap blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario5_allowsV3SwapWithSlippageProtection() public view {
        bytes memory data = abi.encodeWithSelector(
            V3_SWAP_SEL,
            address(0x1),
            address(0x2),
            uint24(3000),
            address(this),
            block.timestamp + 100,
            1 ether,
            0.95 ether,
            uint160(0)
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario5_revertsMalformedV2Swap() public {
        bytes memory data = hex"38ed1739";
        vm.expectRevert("SG: malformed swap calldata");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario5_revertsMalformedV3Swap() public {
        bytes memory data = hex"414bf389";
        vm.expectRevert("SG: malformed swap calldata");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    // ----------------------------------------------------------------
    // Scenario 6: Modern drainers & trace-protected exploit vectors (Blocked)
    // ----------------------------------------------------------------

    function test_scenario6_revertsSetApprovalForAllTrue() public {
        bytes memory data = abi.encodeWithSelector(
            SET_APPROVAL_FOR_ALL_SEL,
            address(0xBAD),
            true
        );
        vm.expectRevert("SG: setApprovalForAll blocked");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario6_allowsSetApprovalForAllFalse() public view {
        bytes memory data = abi.encodeWithSelector(
            SET_APPROVAL_FOR_ALL_SEL,
            address(0xBAD),
            false
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario6_revertsPermit2ExceedingCap() public {
        bytes memory data = abi.encodeWithSelector(
            PERMIT2_APPROVE_SEL,
            address(0x1),
            address(0xBAD),
            uint160(MAX_VALUE + 1),
            uint48(block.timestamp + 100)
        );
        vm.expectRevert("SG: permit2 amount exceeds cap");
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario6_allowsPermit2WithinCap() public view {
        bytes memory data = abi.encodeWithSelector(
            PERMIT2_APPROVE_SEL,
            address(0x1),
            address(0x2),
            uint160(MAX_VALUE),
            uint48(block.timestamp + 100)
        );
        policy.checkTransaction(ALLOWED_TARGET, 0, data);
    }

    function test_scenario6_revertsUnverifiedTarget() public {
        vm.expectRevert("SG: target not whitelisted");
        policy.checkTransaction(BLOCKED_TARGET, 0, "");
    }

    // ----------------------------------------------------------------
    // Fuzz tests
    // ----------------------------------------------------------------

    function testFuzz_valueCapEnforced(uint256 value) public {
        if (value <= MAX_VALUE) {
            policy.checkTransaction(ALLOWED_TARGET, value, "");
        } else {
            vm.expectRevert("SG: value exceeds max per tx");
            policy.checkTransaction(ALLOWED_TARGET, value, "");
        }
    }
}

