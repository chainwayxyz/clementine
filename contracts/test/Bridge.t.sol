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

    function testEcrecover() public {
        bytes32 txid = bytes32(0x0101010101010101010101010101010101010101010101010101010101010101);
        address deposit_address = address(bytes20(hex"0202020202020202020202020202020202020202"));
        bytes32 _hash = bytes32(0x0303030303030303030303030303030303030303030303030303030303030303);
        bytes32 r = bytes32(0x671f033d7227232c55574b5303c9768f1e30b7380ed225513c90f6a0863d10c0);
        bytes32 s = bytes32(0x2f69c3ef60d0f93826ff2f6cbb60bfd98b0fe64ed2c4414ad56ac260821d42e9);
        uint8 v = 28;
        address expected = address(bytes20(hex"aeaacede3c928c31d2572dc8de0f0e93d1f84200"));

        bytes32 messageHash = bridge.getMessageHash(txid, deposit_address, _hash);
        assertEq(ecrecover(messageHash, v, r, s), expected);
    }
}
