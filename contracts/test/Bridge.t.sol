// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/Bridge.sol";

contract CounterTest is Test {
    Bridge public bridge;

    function setUp() public {
        bridge = new Bridge(31);
    }

    function testZeros() public {
        bytes32 zero = bridge.ZERO_VALUE();
        assertEq(zero, bridge.zeros(0));
        for (uint32 i = 1; i < 33; i++) {
            zero = bridge.hashLeftRight(zero, zero);
            assertEq(zero, bridge.zeros(i));
        }
    }

    function testInsert() public {
        bytes32 a = bytes32(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        bytes32 b = bytes32(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        bytes32 c = bytes32(0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc);
        bridge.forceDeposit(a); // just insert
        bridge.forceDeposit(b); // just insert
        bridge.forceDeposit(c); // just insert
        assertEq(bridge.getRootDepositTree(), bytes32(0x6581d50c236d6eabbaef76015b020f1a0f380f83e46b073432a78343243f84fe));
    }
}
