// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/access/Ownable.sol";
import "bitcoin-spv/solidity/contracts/ValidateSPV.sol";
import "bitcoin-spv/solidity/contracts/BTCUtils.sol";

import "./MerkleTree.sol";

/// @title Bridge contract of Clementine
/// @author Citrea

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

    /// @notice Sets the expected first transaction output of a deposit transaction on Bitcoin, which signifies the multisig address on Bitcoin
    /// @dev TxOut0 is derived from the multisig on Bitcoin so it stays constant as long as the multisig doesn't change
    /// @param _depositTxOut0 The new expected first transaction output of a deposit transaction on Bitcoin
    function setDepositTxOut0(bytes calldata _depositTxOut0) public onlyOwner {
        bytes memory oldDepositTxOut0 = DEPOSIT_TXOUT_0;
        DEPOSIT_TXOUT_0 = _depositTxOut0;
        emit DepositTxOutUpdate(oldDepositTxOut0, DEPOSIT_TXOUT_0);
    }

    /// @notice Checks if funds 1 BTC is sent to the bridge multisig on Bitcoin, and if so, sends 1 cBTC to the receiver
    /// @param version The version of the Bitcoin transaction
    /// @param vin The transaction inputs
    /// @param vout The transaction outputs
    /// @param locktime Locktime of the Bitcoin transaction
    /// @param intermediate_nodes -
    /// @param block_header Block header of the Bitcoin block that the deposit transaction is in
    /// @param index Index of the transaction in the block
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

    /// @notice Accepts 1 cBTC from the sender and inserts this withdrawal request of 1 BTC on Bitcoin into the Merkle tree so that later on can be processed by the operator 
    /// @param bitcoin_address The Bitcoin address of the receiver
    function withdraw(bytes32 bitcoin_address) public payable {
        require(msg.value == DEPOSIT_AMOUNT, "Invalid withdraw amount");
        insertWithdrawalTree(bitcoin_address);
        emit Withdrawal(bitcoin_address, nextIndex, block.timestamp);
    }
    
    /// @notice Batch version of `withdraw` that can accept multiple cBTC
    /// @dev Takes in multiple Bitcoin addresses as recipient addresses should be unique
    /// @param bitcoin_addresses The Bitcoin addresses of the receivers
    function batchWithdraw(bytes32[] calldata bitcoin_addresses) public payable {
        require(msg.value == DEPOSIT_AMOUNT * bitcoin_addresses.length, "Invalid withdraw amount");
        for (uint i = 0; i < bitcoin_addresses.length; i++) {
            insertWithdrawalTree(bitcoin_addresses[i]);
            emit Withdrawal(bitcoin_addresses[i], nextIndex, block.timestamp);
        }
    }

    /// @notice Checks if passed in Bitcoin block hash exists in the list of block hashes
    /// @param block_hash The queried block hash 
    function isCorrectBlockHash(bytes32 block_hash) public view returns (bool) {
        return blockHashes[block_hash];
    }

    /// @notice Adds a block hash to the list of block hashes
    /// @param block_hash The block hash to be added
    function addBlockHash(bytes32 block_hash) public onlyOwner {
        blockHashes[block_hash] = true;
        emit BlockHashAdded(block_hash);
    }

    /// @notice Checks if two byte sequences are equal
    /// @dev This is not efficient, and a better approach would be doing a hash based comparison but as this is ran in a zkEVM, hashing is inefficient 
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
