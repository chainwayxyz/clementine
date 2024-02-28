// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/Bridge.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

// !!! WARNINGS:
// !!! - Update `testDepositThenWithdraw` with proper testing of withdrawal tree root if this goes to production
// !!! - Write fuzz tests for deposit and withdraw actions with random Bitcoin txns if this goes to production

contract BridgeHarness is Bridge {
    constructor(uint32 _levels) Bridge(_levels) {}
    function isBytesEqual_(bytes memory a, bytes memory b) public pure returns (bool result) {
        result = super.isBytesEqual(a, b);
    }
}

contract BridgeTest is Test {
    uint constant DEPOSIT_AMOUNT = 100_000_000;
    BridgeHarness public bridge;
    bytes4 version = hex"02000000";
    bytes vin = hex"01335d4a3454d976220232738ca03a7f3456f2e31625b31ae484696d2669083b720000000000fdffffff";
    bytes vout = hex"03c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb050000000000000000166a14d5463b64bb3ecd7501283145600b763c3137b4d04a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    bytes4 locktime = hex"00000000";
    bytes intermediate_nodes = hex"b2fd785590896305ab9c3dd8453acfdb6d3d0538ce72f10e9e720e5c39ba1aa61918d0dd24910a182354cbf2f9e1c85e56e176afdc0763f04186f367d0d1434e936800c1e088f80a692cc8af3c6d3afa7f3d6fcead06b53739de44e67fce59533dffa19f80d5a8a0c9698bb096ae937d4a9a31640cf40da4c923e8833448de33";    
    bytes block_header = hex"00000020bc9079764fe41a13327a9f1b99931b18b34d60d3947f956949eec5c1af5cb80d0a76a7d6a942436f382e259c20d0c5fee06b12799b491683f9c418311e83e224fe28d765ffff7f2001000000";
    uint index = 11;

    address depositor = makeAddr("citrea_depositor");

    function setUp() public {
        bridge = new BridgeHarness(31);

        bytes32 expected_blockhash = hex"b25d57f9acbf22e533b0963b47d91b11bdef9da9591002b1ef4e3ef856aec80e";
        // Owner adds the expected block hash of the block as an accepted block hash containing the transaction above
        bridge.addBlockHash(expected_blockhash);
    }

    function testZeros() public {
        bytes32 zero = bridge.ZERO_VALUE();
        assertEq(zero, bridge.zeros(0));
        assertEq(zero, keccak256("CITREA"));
        for (uint32 i = 1; i < 33; i++) {
            zero = bridge.hashLeftRight(zero, zero);
            assertEq(zero, bridge.zeros(i));
        }
    }

    function testDeposit() public {
        // An arbitrary user makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        vm.startPrank(depositor);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, index, timestamp);

        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));

        // Assert if minted
        assertEq(bridge.balanceOf(receiver), DEPOSIT_AMOUNT);
        vm.stopPrank();
    }

    // TODO: Replace the logic of testing the root of withdrawal tree in a more proper manner if this goes into production
    function testDepositThenWithdraw() public {
        // An arbitrary user makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        vm.startPrank(depositor);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, index, timestamp);

        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));

        // Assert if minted
        assertEq(bridge.balanceOf(receiver), DEPOSIT_AMOUNT);
        vm.stopPrank();

        // Assert if receiver can withdraw
        vm.startPrank(receiver);
        bytes32 bitcoin_address = hex"1234"; // Dummy Bitcoin address
        bytes32 withdrawal_root = bridge.getRootWithdrawalTree();
        bridge.withdraw(bitcoin_address);
        bytes32 updated_withdrawal_root = bridge.getRootWithdrawalTree();
        
        // Assert if tokens are burned from receiver
        assertEq(bridge.balanceOf(receiver), 0);

        // Assert if withdrawal root is updated
        assert(withdrawal_root != updated_withdrawal_root);
        bytes32 expected_root = 0x574330cc8e4db82e36b5daf43915ccb2bf785ac361c3882cc4cdd2a13183af99; // Calculate with another implementation of merkle tree
        assertEq(updated_withdrawal_root, expected_root);

        vm.stopPrank();
    }

    function testCannotDoubleDepositWithSameTx() public {
        testDeposit();
        vm.expectRevert("txId already spent");
        testDeposit();
    }

    function testCannotDepositIfCallExpired() public {
        // An arbitrary user makes a deposit for the `receiver` address specified in the second output of above Bitcoin txn
        vm.startPrank(depositor);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert("timestamp too old");
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, index, timestamp);
    }

    function testCannotDepositWithFalseProof() public {
        vin = hex"1234";
        vm.startPrank(depositor);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        vm.expectRevert("Proof failed.");
        bridge.deposit(version, vin, vout, locktime, intermediate_nodes, block_header, index, timestamp);
    }

    function testCannotDepositWithFalseBlockHash() public {
        block_header = hex"1234";
        vm.startPrank(depositor);
        bytes4 timestamp = bytes4(uint32(block.timestamp));
        vm.expectRevert("incorrect block hash");
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
