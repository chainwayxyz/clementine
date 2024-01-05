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

    function testDeposit() public {
        address[] calldata _verifiers = [address(0), address(0)];
        bridge.setVerifiers(_verifiers);
    }

    function testEcrecover() public {
        bytes32 txid = bytes32(0x0000000000000000000000000000000000000000000000000000000000000000);
        address deposit_address = address(bytes20(hex"a29e4e109a4252daafe55688e49ed129a44e696a"));
        bytes32 _hash = bytes32(0x0303030303030303030303030303030303030303030303030303030303030303);
        bytes4 timestamp = bytes4(0x02020202);
        bytes32 r = bytes32(0x75fecce6cec027e9f0f543c1a3e1e87422e8a30abca443407dfa8a237ce7c2a2);
        bytes32 s = bytes32(0x08273eb26ec79092833e563917061c63ec992bf1eecea49ae42110b222f8fac3);
        uint8 v = 27;
        address expected = address(bytes20(hex"a29e4e109a4252daafe55688e49ed129a44e696a"));

        bytes32 messageHash = bridge.getMessageHash(txid, deposit_address, _hash, timestamp);
        assertEq(ecrecover(messageHash, v, r, s), expected);
    }
}
