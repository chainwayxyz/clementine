// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import "./MerkleTree.sol";

contract Bridge is MerkleTree, ERC20, Ownable {
    uint256 numVerifiers;
    mapping(uint256 => address) public verifiers;

    event Deposit(bytes32  txid, uint32 indexed leafIndex, uint256 timestamp);
    event Withdrawal(bytes32  bitcoin_address, uint32 indexed leafIndex, uint256 timestamp);

    constructor(uint32 _levels) ERC20("wBTC", "wBTC") MerkleTree(_levels) Ownable(msg.sender) {}

    function setVerifiers(address[] calldata _verifiers) public onlyOwner {
        numVerifiers = _verifiers.length;
        for (uint256 i = 0; i < _verifiers.length; i++) {
            verifiers[i] = _verifiers[i];
        }
    }

    function getMessageHash(bytes32 txid, address deposit_address, bytes32 _hash, uint256 index)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(txid, deposit_address, _hash, index));
    }

    /// @notice          Implements bitcoin's hash256 (double sha2)
    /// @dev             abi.encodePacked changes the return to bytes instead of bytes32
    /// @param _b        The pre-image
    /// @return          The digest
    function hash256(bytes32 _b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(_b))));
    }

    function deposit(
        bytes32 txid,
        address deposit_address,
        bytes32 preimage,
        bytes32[] calldata r,
        bytes32[] calldata s,
        uint8[] calldata v
    ) public {
        require(r.length == numVerifiers, "r length mismatch");
        require(s.length == numVerifiers, "s length mismatch");
        require(v.length == numVerifiers, "v length mismatch");
        bytes32 _hash = hash256(preimage);
        bytes32 messageHash = getMessageHash(txid, deposit_address, _hash, depositTree.nextIndex);
        for (uint256 i = 0; i < numVerifiers; i++) {
            require(ecrecover(messageHash, v[i], r[i], s[i]) == verifiers[i], "invalid signature");
        }
        insertDepositTree(txid);
        emit Deposit(txid, depositTree.nextIndex, block.timestamp);
        _mint(deposit_address, 100_000_000);
    }

    function withdraw(bytes32 bitcoin_address) public {
        _burn(msg.sender, 100_000_000);
        insertWithdrawalTree(bitcoin_address);
        emit Withdrawal(bitcoin_address, withdrawalTree.nextIndex, block.timestamp);
    }

    function forceDeposit(bytes32 txid) public onlyOwner {
        insertDepositTree(txid);
        emit Deposit(txid, depositTree.nextIndex, block.timestamp);
    }

        /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view override returns (uint8) {
        return 8;
    }
}
