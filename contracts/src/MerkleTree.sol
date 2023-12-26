// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract MerkleTree {
    bytes32 public constant ZERO_VALUE = 0xf9194e73f9e9459e3450ea10a179cdf77aafa695beecd3b9344a98d111622243;

    uint32 public immutable levels;

    // Separate state variables for each tree
    struct MerkleTreeData {
        mapping(uint256 => bytes32) filledSubtrees;
        bytes32 root;
        uint32 nextIndex;
    }

    MerkleTreeData public depositTree;
    MerkleTreeData public withdrawalTree;

    constructor(uint32 _levels) {
        levels = _levels;
        initializeTree(depositTree);
        initializeTree(withdrawalTree);
    }

    function initializeTree(MerkleTreeData storage tree) internal {
        for (uint32 i = 0; i < levels; i++) {
            tree.filledSubtrees[i] = zeros(i);
        }
        tree.root = zeros(levels);
    }

    function hashLeftRight(bytes32 _left, bytes32 _right) public pure returns (bytes32 value) {
        return sha256(abi.encodePacked(_left, _right));
    }

    function _insert(MerkleTreeData storage tree, bytes32 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = tree.nextIndex;
        require(_nextIndex != uint32(2) ** levels, "Merkle tree is full. No more leaves can be added");
        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;
        bytes32 left;
        bytes32 right;

        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                tree.filledSubtrees[i] = currentLevelHash;
            } else {
                left = tree.filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = hashLeftRight(left, right);
            currentIndex /= 2;
        }

        tree.root = currentLevelHash;
        tree.nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    // Insert functions for each tree
    function insertDepositTree(bytes32 _leaf) public returns (uint32 index) {
        return _insert(depositTree, _leaf);
    }

    function insertWithdrawalTree(bytes32 _leaf) public returns (uint32 index) {
        return _insert(withdrawalTree, _leaf);
    }

    // Get root functions for each tree
    function getRootDepositTree() public view returns (bytes32) {
        return depositTree.root;
    }

    function getRootWithdrawalTree() public view returns (bytes32) {
        return withdrawalTree.root;
    }

    /// @dev provides Zero (Empty) elements for a MiMC MerkleTree. Up to 32 levels
    function zeros(uint256 i) public pure returns (bytes32) {
        if (i == 0) {
            return bytes32(0xf9194e73f9e9459e3450ea10a179cdf77aafa695beecd3b9344a98d111622243);
        } else if (i == 1) {
            return bytes32(0xee9a75010528c31bae7230d36ded16fe2d78f7d87e1b334c9b6b9e4cd0db427c);
        } else if (i == 2) {
            return bytes32(0x829b2ea0d8c96cf1d569c30efd69bd411064a169fde094d7e29410dc5f259f9b);
        } else if (i == 3) {
            return bytes32(0x58c9577fb3953a2f48fe9c01138947add374d2da3fd043a901987a3896ba2c38);
        } else if (i == 4) {
            return bytes32(0x543436d9bf8dcaa93f87f862cc25f01a5b9b990d0528bbb34db5b20fe23177ca);
        } else if (i == 5) {
            return bytes32(0x7a7f7c5edd1b66773e43ff63384d7144c7ddf9134342fdf597bcee9722c4f01e);
        } else if (i == 6) {
            return bytes32(0x70caca61cb222dd2c194f1458c2f906bce68180a923ae0f93e704208b435dac1);
        } else if (i == 7) {
            return bytes32(0x94938614907f9f1a099778bff6a7d67e5abfce8af250feb5c645f607a2736290);
        } else if (i == 8) {
            return bytes32(0x44e77f01d80a0c78b9f45d2493d688af484c4dd6576716a58414b5c8509ed12f);
        } else if (i == 9) {
            return bytes32(0x50f36f4bea8cfee78bac96c076473e4156226e14b59a533db5ef1d5dd1b00529);
        } else if (i == 10) {
            return bytes32(0x9a1eaa80972177ef309226792278ee55dd414bb685a70d47c62a337f0ecf093d);
        } else if (i == 11) {
            return bytes32(0x67f2f4d72d47732f8b8ec11bbb8f15611017231b94e1a85ab20fa00bbc5ed537);
        } else if (i == 12) {
            return bytes32(0x4801f9b6396fabfa26c36bf42dd5d02e92c15b24b2508dfac78b644b35068fa5);
        } else if (i == 13) {
            return bytes32(0x9b64d588d305c76ad1644f0c874964e73e702f4b18499071c11a8c86bfbf7c66);
        } else if (i == 14) {
            return bytes32(0x9daea9513fa9e6d4aee0c81e5b9e601f86825c9e5c7c3f7d309d53400fa95902);
        } else if (i == 15) {
            return bytes32(0x3db567e25654363de4f4c7f78631d15f1346bfce49524f7281b9af144d2eca55);
        } else if (i == 16) {
            return bytes32(0x4641dcf992fe6c30347937173cdd37dc4a8e6e2571f09fa41bcd23a4cc1ea5d0);
        } else if (i == 17) {
            return bytes32(0x3f5bed4f894ea41a794cea78860787335ad888bb57e050341fbfcdcbddf015ff);
        } else if (i == 18) {
            return bytes32(0x948c2327e459df1592c4a22c2afaedf97cc3045f50a9153dcbd849afe69055d0);
        } else if (i == 19) {
            return bytes32(0x0f4f18a68e990becf1a267bd8cdc1ea20b096ae80121a727af7ebafc12d7188c);
        } else if (i == 20) {
            return bytes32(0x00ec3459e2b585f2ccc70d2dbd2b296a7c9b01fdbbbd3ee7a8545fd4e06c6be5);
        } else if (i == 21) {
            return bytes32(0x956ed32b8b4f05ff134c62cb7dfb940270052816cf98f8267876846dbeee5615);
        } else if (i == 22) {
            return bytes32(0x2da5de41f9246c5418125de9b56bc7c268635e3ee087a8c11e75f8773746e88d);
        } else if (i == 23) {
            return bytes32(0x1ba1be98ea5e8139a579f96b85645736d453ec7b8b960d7852bae09ab56e939c);
        } else if (i == 24) {
            return bytes32(0xb3c3960fb2cedd8796341dba0c65c8b57a279876b21050a9196489b62a9e34f7);
        } else if (i == 25) {
            return bytes32(0xce19fabc753e314ed8379f89eff72f179a10a12b2dc4d29f5acffac0c90abd7a);
        } else if (i == 26) {
            return bytes32(0x09f3979f9eb43a58b84b15fe5cf9fd80c75fe2163823a10086b686e64e1501a6);
        } else if (i == 27) {
            return bytes32(0xc718633766f6f743a068de0bcc99b7a9ba8ff9980e118a31a38d71859aac3484);
        } else if (i == 28) {
            return bytes32(0x43cb14ce884b3fa9c8e67270bb47e8dc8f98d539e5107b4ea082c38449caaec1);
        } else if (i == 29) {
            return bytes32(0xa937533683394824f0819a726ff2af9297710e9d0ca8c98429c66a08c25b22a1);
        } else if (i == 30) {
            return bytes32(0xf70815f407682f19ed6efdb3787cfb888d98c7c8e248160cfe3e23b1b63ea07d);
        } else if (i == 31) {
            return bytes32(0x0a4b513a536a9cac3cd32bc8ad1a360f2d71eec72292c4ff56247d516130559e);
        } else if (i == 32) {
            return bytes32(0x1ac67188d859a9cac45fd25c12c3e13ea396a1d789bafa8bae733f84278f0f05);
        } else {
            revert("Index out of bounds");
        }
    }
}
