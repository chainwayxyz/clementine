// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/Bridge.sol";

contract BridgeHarness is Bridge {
    constructor(uint32 _levels) Bridge(_levels) {}
    function isBytesEqual_(bytes memory a, bytes memory b) public returns (bool result) {
        result = super.isBytesEqual(a, b);
    }
}

contract BridgeTest is Test {
    BridgeHarness public bridge;

    function setUp() public {
        bridge = new BridgeHarness(31);
    }

    function testZeros() public {
        bytes32 zero = bridge.ZERO_VALUE();
        assertEq(zero, bridge.zeros(0));
        for (uint32 i = 1; i < 33; i++) {
            zero = bridge.hashLeftRight(zero, zero);
            assertEq(zero, bridge.zeros(i));
        }
    }

    function testDeposit() public {
        bytes4 version = hex"02000000";
        bytes memory vin = hex"01335d4a3454d976220232738ca03a7f3456f2e31625b31ae484696d2669083b720000000000fdffffff";
        bytes memory vout = hex"03c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb050000000000000000166a14d5463b64bb3ecd7501283145600b763c3137b4d04a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
        bytes4 locktime = hex"00000000";
        bytes memory intermediate_nodes = hex"b2fd785590896305ab9c3dd8453acfdb6d3d0538ce72f10e9e720e5c39ba1aa61918d0dd24910a182354cbf2f9e1c85e56e176afdc0763f04186f367d0d1434e936800c1e088f80a692cc8af3c6d3afa7f3d6fcead06b53739de44e67fce59533dffa19f80d5a8a0c9698bb096ae937d4a9a31640cf40da4c923e8833448de33";
        
        bytes32 expected_blockhash = hex"b25d57f9acbf22e533b0963b47d91b11bdef9da9591002b1ef4e3ef856aec80e";
        bytes memory block_header = hex"00000020bc9079764fe41a13327a9f1b99931b18b34d60d3947f956949eec5c1af5cb80d0a76a7d6a942436f382e259c20d0c5fee06b12799b491683f9c418311e83e224fe28d765ffff7f2001000000";
        uint index = 11;

        bridge.addBlockHash(expected_blockhash);
        address user = makeAddr("okko");
        vm.startPrank(user);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, index, timestamp);
    }

    function testBytesEqual() public {
        bytes memory a = hex"1234";
        bytes memory b = hex"1234";
        bytes memory c = hex"1235";
        bytes memory d = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb05";
        bytes memory e = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb06";
        bytes memory f = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb05";

        assert(bridge.isBytesEqual_(a, b));
        assert(!bridge.isBytesEqual_(a, c));
        assert(!bridge.isBytesEqual_(d, e));
        assert(bridge.isBytesEqual_(d, f));

        vm.expectRevert();
        bridge.isBytesEqual_(a, d);

        vm.expectRevert();
        bridge.isBytesEqual_(a, hex"");
    }

    function testBytesEqualFuzz(bytes memory a, bytes memory b) public {
        vm.assume(a.length == b.length);
        assertEq(isKeccakEqual(a, b), bridge.isBytesEqual_(a, b));
    }

    function testBytesEqualForEqualInputsFuzz(bytes memory a) public {
        assertEq(isKeccakEqual(a, a), bridge.isBytesEqual_(a, a));
    }

    function isKeccakEqual(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
}
