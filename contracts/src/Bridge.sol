// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/access/Ownable.sol";
import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

import "./MerkleTree.sol";

contract Bridge is MerkleTree, Ownable {
    bytes public DEPOSIT_TXOUT_0 = hex"c2ddf50500000000225120fc6eb6fa4fd4ed1e8519a7edfa171eddcedfbd0e0be49b5e531ef36e7e66eb05"; 
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;
    mapping(bytes32 => bool) public blockHashes;
    mapping(bytes32 => bool) public spentTxIds;

    event Deposit(bytes32  txId, uint256 timestamp);
    event Withdrawal(bytes32  bitcoin_address, uint32 indexed leafIndex, uint256 timestamp);
    event DepositTxOutUpdate(bytes oldExpectedVout0, bytes newExpectedVout0);
    event BlockHashAdded(bytes32 block_hash);

    constructor(uint32 _levels) MerkleTree(_levels) Ownable(msg.sender) {}

    function setDepositTxOut0(bytes calldata _depositTxOut0) public onlyOwner {
        bytes memory oldDepositTxOut0 = DEPOSIT_TXOUT_0;
        DEPOSIT_TXOUT_0 = _depositTxOut0;
        emit DepositTxOutUpdate(oldDepositTxOut0, DEPOSIT_TXOUT_0);
    }

    function deposit(
        bytes4 version,
        bytes calldata vin,
        bytes calldata vout,
        bytes4 locktime,
        bytes calldata intermediate_nodes,
        bytes calldata block_header,
        uint index
    ) public {
        bytes32 block_hash = BTCUtils.hash256(block_header);
        require(isCorrectBlockHash(block_hash), "incorrect block hash");

        bytes32 extracted_merkle_root = BTCUtils.extractMerkleRootLE(block_header);
        bytes32 txId = ValidateSPV.calculateTxId(version, vin, vout, locktime);
        require(!spentTxIds[txId], "txId already spent");
        spentTxIds[txId] = true;

        bool result = ValidateSPV.prove(txId, extracted_merkle_root, intermediate_nodes, index);
        require(result, "SPV Verification failed.");

        // First output is always the bridge utxo, so it should be constant
        bytes memory output1 = BTCUtils.extractOutputAtIndex(vout, 0);
        require(isBytesEqual(output1, DEPOSIT_TXOUT_0), "Incorrect Deposit TxOut");

        // Second output is the receiver of tokens
        bytes memory output2 = BTCUtils.extractOutputAtIndex(vout, 1);
        bytes memory output2_ext = BTCUtils.extractOpReturnData(output2);
        address receiver = address(bytes20(output2_ext));
        require(receiver != address(0), "Invalid receiver address");

        emit Deposit(txId, block.timestamp);
        (bool success, ) = receiver.call{value: DEPOSIT_AMOUNT}("");
        require(success, "Transfer failed");
    }

    function withdraw(bytes32 bitcoin_address) public payable {
        require(msg.value == DEPOSIT_AMOUNT, "Invalid withdraw amount");
        insertWithdrawalTree(bitcoin_address);
        emit Withdrawal(bitcoin_address, nextIndex, block.timestamp);
    }

    function isCorrectBlockHash(bytes32 block_hash) public view returns (bool) {
        return blockHashes[block_hash];
    }

    function addBlockHash(bytes32 block_hash) public onlyOwner {
        blockHashes[block_hash] = true;
        emit BlockHashAdded(block_hash);
    }

    function isBytesEqual(bytes memory a, bytes memory b) internal pure returns (bool result) {
        require(a.length == b.length, "Lengths do not match");

        // Cannot use keccak as its costly in ZK environment
        uint length = a.length;
        for (uint i = 0; i < length; i++) {
            if (a[i] != b[i]) {
                result = false;
                return result;
            }
        }
        result = true;
    }
}
