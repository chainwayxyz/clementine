//! # Bitcoin Merkle Tree Implementation
//! This module implements a Bitcoin Merkle tree structure, which is used to verify the integrity of transactions in a block.
//! It provides functions to construct the tree, calculate the root hash, and verify the inclusion of transactions.
//! The tree is designed to be secure against certain types of attacks, particularly in the context of Simplified Payment Verification (SPV).
//! It also includes a "mid-state" tree for generating secure SPV proofs.
//! **⚠️ Warning:** Use the `new_mid_state` function for secure SPV proofs, as the standard tree is vulnerable to certain attacks.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::common::hashes::{calculate_double_sha256, calculate_sha256};

use super::transaction::CircuitTransaction;

/// Represents a Bitcoin Merkle tree.
#[derive(Debug, Clone)]
pub struct BitcoinMerkleTree {
    nodes: Vec<Vec<[u8; 32]>>,
}

impl BitcoinMerkleTree {
    /// Constructs a standard Bitcoin Merkle tree.
    /// Leaf nodes are transaction IDs (txids), which are double-SHA256 hashes of transaction data.
    /// Internal nodes are formed by `DSHA256(LeftChildHash || RightChildHash)`.
    /// WARNING! Do not use this tree to generate SPV proofs, as it is vulnerable to certain attacks. See
    /// `new_mid_state`.
    pub fn new(txids: Vec<[u8; 32]>) -> Self {
        if txids.len() == 1 {
            // root is the coinbase txid
            return BitcoinMerkleTree { nodes: vec![txids] };
        }

        let mut tree = BitcoinMerkleTree { nodes: vec![txids] };

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = tree.nodes[0].len();
        let mut prev_level_index_offset = 0;
        let mut preimage: [u8; 64] = [0; 64];
        while prev_level_size > 1 {
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                if tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2]
                    == tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1]
                {
                    // This check helps prevent certain attacks involving duplicate hashes,
                    // although the primary defense against CVE-2012-2459 and similar issues
                    // in SPV often requires more structural changes or careful proof verification,
                    // which the `new_mid_state` tree aims to provide. For more, please check:
                    // https://github.com/bitcoin/bitcoin/blob/31d3eebfb92ae0521e18225d69be95e78fb02672/src/consensus/merkle.cpp#L9
                    panic!("Duplicate hashes in the Merkle tree, indicating mutation");
                }
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            prev_level_size = prev_level_size.div_ceil(2);
            prev_level_index_offset = 0;
        }
        tree
    }

    /// Returns the Merkle root. Use this only for Bitcoin merkle tree, not for mid-state trees.
    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.nodes.len() - 1][0]
    }

    /// Constructs a "mid-state" Merkle tree, designed for generating secure SPV (Simplified Payment Verification) proofs.
    /// This structure, when used with the corresponding `calculate_root_with_merkle_proof` (or `BlockInclusionProof::get_root`) method,
    /// helps mitigate vulnerabilities associated with standard Bitcoin Merkle trees in SPV contexts, such as certain forms of hash duplication or ambiguity attacks (e.g., CVE-2012-2459).
    /// Also please check:
    /// <https://bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/> with the suggested fix:
    /// <https://bitslog.com/2018/08/21/simple-change-to-the-bitcoin-merkleblock-command-to-protect-from-leaf-node-weakness-in-transaction-merkle-tree/>
    ///
    /// The leaves of this tree are transaction identifiers (`mid_state_txid()`), not typically standard Bitcoin txids (double-SHA256 of the transaction).
    /// The internal nodes of this "mid-state" tree are constructed differently from a standard Bitcoin Merkle tree:
    /// `N_parent = SHA256(SHA256(N_child_left) || SHA256(N_child_right))`
    /// where `N_child_left` and `N_child_right` are nodes from the level below in this mid-state tree.
    ///
    /// The root of this mid-state tree (`Root_ms`) is an intermediate hash. The actual Bitcoin block Merkle root
    /// is expected to be `SHA256(Root_ms)`, as demonstrated in the test cases.
    ///
    /// The security enhancement for SPV comes from how proofs generated from this tree are verified:
    /// specifically, sibling nodes from this tree's proof path are further hashed with `SHA256`
    /// before being combined in the standard `double_SHA256` Merkle path computation during proof verification (see `BlockInclusionProof::get_root`).
    /// This acts as a domain separation, ensuring that the internal nodes of this mid-state tree cannot be misinterpreted
    /// as leaf txids or other hash types during verification.
    pub fn new_mid_state(transactions: &[CircuitTransaction]) -> Self {
        if transactions.len() == 1 {
            // root is the coinbase mid-state txid
            return BitcoinMerkleTree {
                nodes: vec![vec![transactions[0].mid_state_txid()]],
            };
        }

        let mid_state_txids: Vec<[u8; 32]> =
            transactions.iter().map(|tx| tx.mid_state_txid()).collect();

        let mut tree = BitcoinMerkleTree {
            nodes: vec![mid_state_txids], // Level 0: Leaf nodes (mid-state txids)
        };

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = tree.nodes[0].len();
        let mut preimage: [u8; 64] = [0; 64]; // Preimage for SHA256(SHA256(LeftChild) || SHA256(RightChild))
        while prev_level_size > 1 {
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                let left_child_node = tree.nodes[curr_level_offset - 1][i * 2];
                let right_child_node = tree.nodes[curr_level_offset - 1][i * 2 + 1];

                if left_child_node == right_child_node {
                    // This check is also present in the mid-state tree construction.
                    // While the primary defense is in the proof verification, preventing duplicate
                    // inputs at this stage is good practice.
                    panic!("Duplicate hashes in the Merkle tree, indicating mutation");
                }
                // Preimage construction: SHA256(LeftChildNode) || SHA256(RightChildNode)
                preimage[..32].copy_from_slice(&calculate_sha256(&left_child_node));
                preimage[32..].copy_from_slice(&calculate_sha256(&right_child_node));
                // The new node is SHA256 of this preimage
                let combined_mid_state_hash = calculate_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_mid_state_hash);
            }
            // Handle odd number of nodes at the previous level by duplicating the last node's hash processing
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                let last_node = tree.nodes[curr_level_offset - 1][prev_level_size - 1];
                // Preimage: SHA256(LastNode) || SHA256(LastNode)
                preimage[..32].copy_from_slice(&calculate_sha256(&last_node));
                preimage[32..].copy_from_slice(&calculate_sha256(&last_node));
                let combined_mid_state_hash = calculate_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_mid_state_hash);
            }
            curr_level_offset += 1;
            prev_level_size = prev_level_size.div_ceil(2);
        }
        tree
    }

    /// Given an index, returns the path of sibling nodes from the "mid-state" Merkle tree.
    fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(
            index < self.nodes[0].len() as u32,
            "Index out of bounds when trying to get path from mid-state Merkle tree"
        );
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;

        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                // Current node is a right child, sibling is to the left
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else if (self.nodes[level as usize].len() - 1) as u32 == i {
                // Current node is a left child and the last one (odd one out)
                path.push(self.nodes[level as usize][i as usize]); // Sibling is itself (implicitly, due to duplication rule)
            } else {
                // Current node is a left child, sibling is to the right
                path.push(self.nodes[level as usize][(i + 1) as usize]);
            }
            level += 1;
            i /= 2;
        }
        path
    }

    /// Generates a Merkle proof for a given index in the "mid-state" Merkle tree.
    pub fn generate_proof(&self, idx: u32) -> BlockInclusionProof {
        let path = self.get_idx_path(idx);
        BlockInclusionProof::new(idx, path)
    }

    /// Calculates the Bitcoin Merkle root from a leaf's mid-state transaction ID (`mid_state_txid`) and its inclusion proof
    /// derived from a "mid-state" Merkle tree. This function is central to secure SPV.
    ///
    /// The `inclusion_proof` contains sibling nodes from the "mid-state" Merkle tree.
    /// The security enhancement lies in how these proof elements are processed:
    /// Each sibling node from the proof path is first hashed with `SHA256` before being
    /// combined with the current hash using the standard Bitcoin `calculate_double_sha256` method.
    ///
    /// `current_hash = calculate_sha256(current_hash || SHA256(sibling_from_mid_state_proof))`
    ///
    /// This transformation of sibling proof elements acts as a domain separator,
    /// robustly distinguishing them from leaf transaction IDs. This prevents vulnerabilities where an
    /// attacker might craft a transaction whose ID could collide with or be misinterpreted as an
    /// internal node of the mid-state tree, or create other ambiguities that could fool an SPV client.
    /// The final `[u8; 32]` returned should match the block's official Merkle root.
    pub fn calculate_root_with_merkle_proof(
        mid_state_txid: [u8; 32], // This is the leaf mid_state_txid (SHA256 of transaction)
        inclusion_proof: BlockInclusionProof,
    ) -> [u8; 32] {
        inclusion_proof.get_root(mid_state_txid)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BlockInclusionProof {
    idx: u32,
    merkle_proof: Vec<[u8; 32]>, // These are sibling nodes from the "mid-state" Merkle tree
}

impl BlockInclusionProof {
    pub fn new(idx: u32, merkle_proof: Vec<[u8; 32]>) -> Self {
        BlockInclusionProof { idx, merkle_proof }
    }

    /// Calculates the Merkle root given a leaf transaction mid-state transaction ID (`mid_state_txid`)
    /// and the Merkle proof path (sibling nodes from the "mid-state" tree).
    ///
    /// The core of the SPV security enhancement is here:
    /// Each `merkle_proof` element (a sibling node from the mid-state tree) is first hashed
    /// with `calculate_sha256`. This transformed hash is then used in the standard Bitcoin
    /// Merkle combination step but with single hash (`calculate_sha256`).
    ///
    /// If `leaf` is the current hash and `P_mid_state` is a sibling from the proof path:
    /// `next_hash = SHA256(SHA256(leaf) || SHA256(P_mid_state))` (or reversed order).
    ///
    /// This ensures that elements from the mid-state tree's structure are treated distinctly
    /// from the leaf transaction IDs, preventing cross-interpretation and related attacks.
    /// The final hash should be the main Bitcoin block Merkle root.
    pub fn get_root(&self, mid_state_txid: [u8; 32]) -> [u8; 32] {
        // mid_state_txid is the leaf but the transaction is hashed with SHA256, not DSHA256.
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = mid_state_txid;
        let mut index = self.idx;
        let mut level: u32 = 0;
        while level < self.merkle_proof.len() as u32 {
            // Get the sibling node from the mid-state tree proof path
            let mid_state_sibling_node = self.merkle_proof[level as usize];
            // Secure SPV step: transform the mid-state sibling node by SHA256-ing it
            // before using it in the double-SHA256 combination.
            let processed_sibling_hash = calculate_sha256(&mid_state_sibling_node);
            let processed_combined_hash = calculate_sha256(&combined_hash);

            if index % 2 == 0 {
                // `combined_hash` is the left child
                preimage[..32].copy_from_slice(&processed_combined_hash);
                preimage[32..].copy_from_slice(&processed_sibling_hash); // Use the SHA256'd mid-state sibling
                combined_hash = calculate_sha256(&preimage);
            } else {
                // `combined_hash` is the right child
                if processed_sibling_hash == processed_combined_hash {
                    panic!("Merkle proof is invalid: left hash matches combined hash");
                }
                preimage[..32].copy_from_slice(&processed_sibling_hash); // Use the SHA256'd mid-state sibling
                preimage[32..].copy_from_slice(&processed_combined_hash);
                combined_hash = calculate_sha256(&preimage);
            }
            level += 1;
            index /= 2;
        }
        calculate_sha256(&combined_hash) // This should be the Bitcoin block's Merkle root
    }
}

#[cfg(test)]
/// Verifies a Merkle proof against a given root using the "mid-state" tree approach.
///
/// - `mid_state_txid`: The transaction ID of the leaf node for which the proof is provided.
/// - `inclusion_proof`: The proof path containing sibling nodes from the "mid-state" Merkle tree.
/// - `root`: The expected Bitcoin Merkle root of the block.
///
/// This function recalculates the root using `inclusion_proof.get_root()` (which applies the
/// SPV security measure of SHA256-ing mid-state proof elements) and compares it to the expected `root`.
pub fn verify_merkle_proof(
    mid_state_txid: [u8; 32],
    inclusion_proof: &BlockInclusionProof,
    root: [u8; 32],
) -> bool {
    let calculated_root = inclusion_proof.get_root(mid_state_txid);
    calculated_root == root
}

#[cfg(test)]
mod tests {

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Block, Transaction};

    use crate::bridge_circuit::transaction::CircuitTransaction;

    use super::*;

    #[test]
    fn test_merkle_tree_0() {
        let block: Block = bitcoin::consensus::deserialize(&hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000004e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a046f3566ffff001dbb0c78170101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5504ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065ffffffff0100f2052a010000002321000000000000000000000000000000000000000000000000000000000000000000ac00000000").unwrap()).unwrap();
        let tx_vec: Vec<CircuitTransaction> = block
            .txdata
            .iter()
            .map(|tx| CircuitTransaction(tx.clone()))
            .collect();
        let txid_vec: Vec<[u8; 32]> = tx_vec.iter().map(|tx| tx.txid()).collect();
        let merkle_tree = BitcoinMerkleTree::new(txid_vec);
        let merkle_root = merkle_tree.root();
        assert_eq!(
            merkle_root,
            block.header.merkle_root.as_raw_hash().to_byte_array()
        );
        let mid_state_merkle_tree = BitcoinMerkleTree::new_mid_state(&tx_vec);
        let mid_state_txid_0 = tx_vec[0].mid_state_txid();
        let merkle_root_from_mid_state = calculate_sha256(&mid_state_merkle_tree.root());
        assert_eq!(
            merkle_root_from_mid_state,
            block.header.merkle_root.as_raw_hash().to_byte_array()
        );
        let merkle_proof_0 = mid_state_merkle_tree.generate_proof(0);
        assert!(verify_merkle_proof(
            mid_state_txid_0,
            &merkle_proof_0,
            merkle_root
        ));
    }

    #[test]
    fn test_merkle_tree_1() {
        let block: Block = bitcoin::consensus::deserialize(&hex::decode("00802926b62577e229ae0009b80da0d948a7c934b3abf34a05e67b7d227780000000000071ff9f8ea5a251fa28934d6920f4c87724ef9a552f0e00a5020b83dc11a13870c8152b67ffff001d5c024aac29010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff270328d20000049af92a67044d1de50a0c71230c6743fc2800000000000a636b706f6f6c032f672fffffffff02249d0a2a01000000160014536182d440abe6e9895e75066fc9dfff1737497f0000000000000000266a24aa21a9ed6d91cee860b3cdbc07e095a9f552381313e65eb266bdee50aa19d0b2ecb7d0c2012000000000000000000000000000000000000000000000000000000000000000000000000001000000000101d0874b7a7f12e721aa7922a3d9e38db39374ecd3124f2575439429f5c9e2c1f40500000000ffffffff56400d030000000000225120e11877100296215d2455ba8ce1e8a5a0ef6959f2407db793b8d310d29e261c93400d030000000000225120012b07d47940bff758004e8c778581598029e9ab3daf65d2f55eb8b188423096400d030000000000225120d61e3e40410a41428e925c6b50ce66cf0674c6172554820796a7a87358483d35400d03000000000022512038c1d55dca433bb034ecf7bf77bf325388769042ce2383aeb74d6bd72fccb7f2400d030000000000225120fed292b6b5b0cd1532fba6c5a268a953e9be5c84ba2392e7083a1d6d965137ad400d0300000000002251205f5e01e0045180729e409a89249970b00354c96898ccc758243caf6f68d2552b400d030000000000225120de43a63c3e2f299dde78dfcb0e633a52831cfe0e50103a680251feaa6723d1c2400d030000000000225120e53a8d91996b0f4ba6d2fe7b5e5937bde509f90aa5f9513bf08b44874dc3c185400d030000000000225120590ca3a044c769a7b5f38a4b332740bc369fcba3acaa37717643c60eac8ea875400d0300000000002251204a2cf1c710d4c14f945e85c6e27d8997cb38848d0b1e4d288ab5085170d3c161400d0300000000002251201d6f2c25286eb2cc3012819f127a6aafdd0751b20ac29bb8f9c517f22c52cbb5400d0300000000002251206e95cc5cf31b3706747bf2973f26468e1a1df4f501e267169dea4f9bf930b489400d030000000000225120e3407288dee0350ed5b865f30d32136c4169e1515c2f9453a6db84c549da0dca400d030000000000225120da195ff8d13386fa3164b35f54452bfd261fc8dc850c826daa9d4ae9b86ffcd5400d030000000000225120a47df510748031845665f3a512d600f3c145a07ce203341e4901ac05393054b1400d030000000000225120e663fc488244551097a3ddc07cc9800925ced00d2d4bb535d7b60a30eb479fc5400d030000000000225120d9bf66a5eed503c925b2f960af19732c795cf1fe7e3ea73f8d7ab995ee875948400d030000000000225120c8bdd7c2e696fee1abe8b322ce9ee3b8bf7bff7546fe0ca9377da75376c1d92c400d0300000000002251203c00aaaf8af2197ecb3417669ca2c1dea09dc354b685af21c7194afec58107a0400d0300000000002251207296a76471c44f42e423c2e7c9dc64c3afa991feec488a135ac54f8a56a3b496400d030000000000225120fca30ebf5b1573b2f7dd7542f6e6796c4927d775f43edf274cc2a7fcf9f2ca66400d030000000000225120cd2a8532ddc4d8510ea9d1d5e7305b1328a53d4b0654d439643d11e33a4ccb5b400d03000000000022512093b5732855048193c1d921468cbf01288433fa6ca98397835cd2b50977a4bcf3400d0300000000002251204d9c4f81ff5788a6aaecf3065bbeec32e610e580852385e9ce1a3f761d065b93400d0300000000002251209955a72ea46122230c6fadeadb39f597841ecdd91ab0b2e832d337b9ed868624400d030000000000225120344c772b4987e8058b44cb09938875d6485283e370b03e6b7f4d651fa1494082400d030000000000225120d7a659d7199a5f54b7d1876b62ba0d6140adecf36b2a3b343f6b0000b395d63f400d03000000000022512071ecff91e39bc6df0f8b194d8df03b0952ecd869f73caecccaf39902651acbf2400d030000000000225120fcdcea1f03bffd488c9f12aafc4392e444b7873c489a05e97f433be7c02d806b400d030000000000225120ffff30e51593bbd7c73cef68bcffdecbc72475fe5664c4be5447ec59773c439e400d0300000000002251204a3ec17459bcbb130a2e5b8a346c3784a132656ae354079206043f737aafd007400d030000000000225120f58b369aa9c9c429f9fda9a5ad56141554ce89b404630ba63fa9d91553a73c60400d030000000000225120187c1036952ece7f6b7de3b008f98847f99984ab4f3e67daef3019f32248b9e2400d030000000000225120d9e5a5ebb0d2f973d80886d30c5e3f7ddb9b3b9414ee6e06fd9f6c36133b53f0400d03000000000022512037223e88dc8e3c653b50572d9ab752e37316e7a37f7b44a4fd83e396e9021c3b400d0300000000002251203954a18199ebddfaeb2b5082835357376cfbb4a4b38ac2fa0ba0261099e5a7b2400d03000000000022512019081384ac60ccd75e5084456d109b1e3007de26a622d9b710c935c2e10dbc1f400d03000000000022512072ec350bec46b2dcf114626d57c13c29bc926f46c12cbd576e4e61f5938366a3400d030000000000225120e8e3351e1a3efa0438587d6f5ad8ccfac3a0c665bc9c17a44ff9fd2e3e7697f4400d030000000000225120cccbc14141bc0091002a6beb74d8b99b1457d06483983ec613ebf003f2175f62400d03000000000022512019a116d71d7bf1bd5db46c917d5e880e965ce4651594e301e625ab2a41295c02400d0300000000002251204c4df805cac8a86e0fa6336df13c708095b26763c2de42154a12a3e16212dac5400d0300000000002251208191e1c629ccf3b79e6b384b775cb76458afbc5103839e4846165d530daf8f47400d0300000000002251201ca3ec0844c8c54a8078fe411fa76b07cfb3aacef40f71cf06765277bef9b8ea400d03000000000022512092b62ac803b726aea1b7f12cacedc19a1e8088c3df73dc5aacb52ee8c9581b1f400d0300000000002251200c0eaa84dc7e7348ba914fbc4a78dc13c8384d23472dd6fa84fca4e435fae4ca400d03000000000022512042ce2f661da192f7aace80066b4f321df3ebf4214afe5ff524d72b42e8bf61a4400d0300000000002251200d411c0396da6f8812ce94e75c9d60545bb1ed5483ae4ff28d9b14a0e97188f0400d0300000000002251200d7538352e5552450cece443a8058637fda3288304126257c7d5288ee790c690400d0300000000002251205393956f43d9470c6ed90f112b41b41140920a1cc67cc84113d3f973378e9302e0fd1c00000000002251200c820a4f62a95168918c3c0fd9b2f74ee6eda157ee83c097e10cf186615cf809400d03000000000022512054e84bf1916f3942dfba58dec5f4c66b0a3ee50f255b9108a6631221c0ce9dfd400d0300000000002251202c7dfd938b5f26a43b9d80fe737a35e120b0cf87b44187466ccc59acd444965e400d03000000000022512035dbbab23efd26df70a6651cdb31c5872e43fdc14e19b30af7ab630ee22e328a400d030000000000225120f16681177c6726e464bf5e345b086aedf2a47e3b89feb30e0e25747c3b851536400d0300000000002251207fb3c0cd398b631233b5672eaef7b47e320d1811967af76b344fde681a2ac457400d030000000000225120f106dfc0e33ea1f69fdc5665946d5542b6ea2445a80c34c49d94418ce11568aa400d030000000000225120d7382ae22ff42d2275f05f646d08e78430ad6605250f8298093021648329d08b400d03000000000022512096024546315188307eaa97e1f52499cec4b386ba69f55553644762ac2816d4e1400d0300000000002251209ce3090c4496d37205d644accd85f767220e40c19c9a94e2fa9b3c61e20a6bd8400d030000000000225120e03067b7a87746c56bd535976a92db840b0a6a46398e95f0e44e832f7ada01bd400d030000000000225120696b672a1a44611c48f3f3a19ec507319e74151df0d551735950276a2f94d0bb400d030000000000225120300d29d3ba0cf354433b8438c28fb0fe492baf28711f5e9668093e3c1fe73a65400d030000000000225120545f606e43b4579ccdb1b04f8a2ae1af32c20082590eaf77fe17a77dfb30a60f400d0300000000002251202ee4b3f2df4adb7b5384a831daf43fcbdb2ba6ead7a11393e990d9ae4001b9c1400d030000000000225120799f5969c69b76169ac8cc43f403baa0f2a7d91f33bee2f7e78a92b7bab44b47400d0300000000002251202f11c5651b4aa0d8d0cf85dfe79c4e29ed9c16c99a9a7cf469ee015886128cba400d0300000000002251203c561e507924f3b1fb587661ec47f6d26aa0eb7106f47242b964b20cb763ea79400d030000000000225120531b37a969e7152f1ff6ce9b4f6f127047d4e7d6cc4e8be91ed81e85d8048e80400d030000000000225120b54bc9b12593990f7eadfa8b2fa87b590a81f0d0d25aa9b048d2bacae177486d400d03000000000022512028b42afac36727c0cdce9b980220dc519721fdde80c6c19c0eaf0f4e86067ac7400d030000000000225120e09e614c027f50038b5f5b6770f52d92b612b58c9d58c53c9151a71a2f2cc014400d030000000000225120c6eb3b061dbfc876399fad6371ca00712d2ea8bf243f0c1bfae02e30076a1da0400d030000000000225120ee4ada4fd527ad86d9370433554436d6e24d615d95cf1d7819069fd348e0ba6140420f0000000000225120c04b15c90149df98fc4679081ff94131329bc23e4319502b2876d90228e3e37d400d03000000000022512050b618aa1953112c692efaff3ec0811edc9a20ccaa42153ea9e58613912a57b5400d030000000000225120d172584c827287cf4b99b17552f8e4d14588b2417d4be6f61afb78cfd1314b56400d0300000000002251202352f368849d1b3e7af24ad9e63e6d633ff5304d61fdbb87cc2900f6356204d9400d03000000000022512040e87325471610a96d70e1641f2ca00a20352a050624b5d6e35c3d138e59e7c7400d030000000000225120350f90cdc8dd7dba36a2445e1b067b43368cded6100f83d3819109dd964fd14c400d0300000000002251207f3a1309add12d2b6387e9375351c49be2d274697311443a8b0e10ceac087e40400d0300000000002251209db5233f2abcaf2780dc1955b6b8cd217a54622b3dac7b6510ba2714963030dd400d030000000000225120c4c95664724ce044ff77c77c24c24aa3c0b0ec289cb574bed6b00e5541ebb72e400d0300000000002251201acc8fde62205048f932c2c7a45b48c1456824516b8c604f78eb143e119c95c9400d03000000000022512067159985de51b57095ed4e20398c2b3d37c2093708751324d22e959852440d3e899c287c01000000160014dbd359f23e01f8752cc193fefc04aaa9e3a441400247304402206731bfecbd6c6e67c3212edbd71debb3e1d92197a953a21ffaacf2a6430e7bb20220575b4092e683e33e6a648447a815e5ddbc4b384edbbbe1a3a71c53f7fbdd0171012102836b1dbc3d40d023ec913ce3d04455a05873ea28e08c6b07536c0f08b3d3d17e00000000010000000001011ba7dcd9d08007bfdb31b27ab323b7958f17549b973a98b721d7108bb40534470100000000ffffffff56400d0300000000002251207022fbb7a6ae628fa593e35e402fbc19ab30cc2991e4eecd5f1ba9aeda50b65e400d030000000000225120903226eae1df825893ceeeaa21f9345a2de523be9325f992ea7fec92b94a5d1e400d03000000000022512017df484096cb1f3cf265653d1926be60b29e77213ae331cbf22d37f1c49934de400d030000000000225120d20bcc3265bf8f7da708df2e8d1964aa17139a39f9b58b7315edb04f6143d9c3400d0300000000002251205cfdf9c25bfa9b527a543234b927f083a020feb2967622e173458e59dcbd0003400d030000000000225120d403abbac8683e0455e1e5736daedc980753d8178991771f1b0d51a6ba82614f400d0300000000002251206e7bca480ddd4f22bbf246e972e8bfdaae1352127f7c303ec7e4f6a8c4b21ad160e3160000000000225120786d148fb2d85e10db8969dba73a7351786b4b7ddb9efcc67436f740598e548d400d03000000000022512049d9c2d0eb093398da626969e25362bbd9d50ee6d71481a6f86c706495fd5989400d0300000000002251206663a8a94c49f429ecaeb68c6be3e41d8636b2f6d088f58f3d591a492cf1d503400d0300000000002251201cafa0d92594feba9f0637f201e7568bf5d702af301f2c14b072b87c12388e5e400d0300000000002251200912ffbf4df4625c1a80142f49258a315e2488a2e33c61d044bf7820dc612b97400d03000000000022512022c066bd646fe5171b175c3bc2b25e189683facdf110b430a7cc3d6e0f510f73400d030000000000225120bd9396e4a61acb9444b1c18e32c252bfe7b835f099bf86bd96de5803c6d77aa1400d030000000000225120553dbce7f9ae57d55b7bf3d7c68aba36d2df67bc0d18b87de56d2601d9e8ab3fe0fd1c00000000002251203e73ce12f41c2d401f7e09e8f3707a593ea9c8081d66624dc556855013bd6ede400d0300000000002251207ec03c57a8075ec4bdc13083692961105b56ce0504b1c5bb09b9588eb523bce9400d0300000000002251205050433441e745276d208bf4f9f1a0137e7a91c7e80838a0f1a3c6a0b104a3d1400d030000000000225120184cacc7a13ea684c3597e7bcf109bee4e6d0aa5133ae8c57fba8ec7e336d3c1400d0300000000002251208816daf591eb7b4f145933093d493e3fea200d332628281b9f16dd46805436db400d030000000000225120e6fda9104c7c50bf0ba89fc5a4440b4fda7f1d1b76e37f3237d97dbdcb27e7d640771b000000000022512005d2303c9e9587fcf515b4afb0e6c2c252b0481f206f5515be05fb90c1fe422ec091210000000000225120a0955ba3445caccba50e66b087220f13050b76afdf954e0835bc107281da0cc9400d030000000000225120755247883535915e6fe04261c1db20f1a08495e60220d7c82b526c9027497847400d030000000000225120f427311e06daa16f076f701d3771b7743f15a22dd46cf932e61adbc6de9a2eac400d0300000000002251209a4b59f038ce312cc7098dd07c99beaadecf90de67e0c27e8a34950a04cad436400d0300000000002251203d02c8c86760c8dd13a75082ecacf3bbf70e2400dbe8626e28072b6216852856400d030000000000225120af8fc5a1cbd1b5ac02e34892bec4a50d9f815276a6be002521c63b557ee292ec400d030000000000225120c256c25d219c833d56bc2102863700f399ddb7793b6f4f0d2b35decb2a943c33400d030000000000225120af112e22c6a8f5181211e7403f5f9975319853da3c72702f5b8099e93c17c158400d03000000000022512093ca9bc3fd3b90978d4ae9d307725acadb1ff9afba72db1876de728e68da5c5d400d030000000000225120ccd8b5a2a3377b7e3e63e6266a41eb7bd9a834a907ca91858df54c485e909753400d03000000000022512096ba1089e3908cc36057a62e4107b566616a8ca67ddc0a66e18df1aedd50cd3a400d030000000000225120ec12ca07b363661532950fcc9b163b33462ed730a5e5a03605aba84914de56e7400d030000000000225120af9d8501ac444b7d958d96845193c485400855cdb8cdaee31b9798b14e9eac87400d030000000000225120a7a67f34d0bdfef934e2dadbd77da915072edd48560ed3602f33b8225256a2b7400d0300000000002251203338a42ead8ba65ae6e71cc2b781f039053a956cc03acd45c266787684122f93400d03000000000022512036287049ce89faae4087e356c6894b4f7efc102639011c2727744a89a4527850400d0300000000002251206e8207ed0b4fc44b417526b97685094b04318bafa32c03f8b9843e440c81879b801a0600000000002251206c9d33e2c4a8bd1054afe49bd88f0867b60b254ffb0e58239b5b31059b4255e3400d030000000000225120064f4ff1ebd592358ec04fa1de7050eb8caec7661bffe74f189c51cd708ff1ed400d030000000000225120733985c6b5bd84dd51d0973d3fca2740b328a71dd462ad1a53fdb8ec119607cd400d030000000000225120916be5e4a2a578a3bcc8b9965b8465777ae5ef796665221eadb8efb55d65b556400d030000000000225120c1bf7325d66a2e2dedc1599b11ba4df74bfdfada9d2b9cd738a9c68dcb32c418400d030000000000225120ce6f2bf1ccb6e96a94ed185ca1d604a62631842cdfba59ffcd4aad101e1b9265e0fd1c000000000022512007e5345ceee2afc72bab07c4a233df90e97c5cea7030591d6cca3063b50f5c70400d0300000000002251206251ae0562566be092857da794aef7a6858bc10c2d92e2df2b67b3e7f2151507400d030000000000225120b58fcb7954419017efbb0c17a04d8121fb921a8c5b1184dc8a2d15920d38d58e400d03000000000022512092c4f29a3dbb840ad3cbabdcfb527ff08fc21f454a2018e71776568d731e1ef3400d030000000000225120fa433de4ec37ba7d13ed94fa294e528d53c587a54d01a0f2dc53069fafd5806d400d0300000000002251208c3a2f8534dfda45ab37f6a8acb0a7119002b7ca2d519bcaaf9d4c24ecf45436400d0300000000002251205c0938706fc4d3a72b98f82a5a239bcc8bdd6b3a7d96a016a5ae67210ea82a3a400d030000000000225120667f7b015d4b113cc9c5d068cd56d5d301f4c04898a5dd4b9117a245082dec77400d030000000000225120d9708045075d338a7a7e0e2236a9cb4ce3e107226e370e55b79e37ee3bdf4e9c006a180000000000225120135da47172343a84f365a427965afe757293cff0ef962983457c116034ac90f9400d030000000000225120bdcfa69f9805759d5929ac2514eae0d53a5ab1d27cbb61a69337674217a85884400d030000000000225120dd54f910695c8e366927cd5d5ec8dd60c3945e620f593a551b3f558e3fd56d85400d0300000000002251207919a59fee2cb97245213c9b4da8f907153ad0ff096ff03d0eb999f93bddecbc400d03000000000022512096ad18837720b09663053e541206b3ef2accb0d4012815bb0e8b603410c69d41400d0300000000002251207273dc83d40445a87b0eae651cab7a08242ac4d972e43eafbdaeae15acdcaee2400d030000000000225120f9c45a63059d3250b2ad77a9fa0a037dacbfa10099dea50f2bda5190c38a0604400d030000000000225120fcb99825e04d6b864970fe4d1558182a5a5810c4674a687f43ee76b3d9738f86400d030000000000225120b4c7f5b5843bffff9166c9e2fb73719bc23019aff8365bd8ed77c1cd1e499f9b400d030000000000225120f5967b69cf197321174329fff226cc716bc36da5b5a5d562a2837c3462f6d594400d0300000000002251207ef2cc1f698411808d202040ca7289e82c95d389a2e8166a584431054b18b22e400d030000000000225120c960a50984fa31471671ce8141b952f34b4d6781b477355880e8c6623bff56dc400d0300000000002251205fadfebdba8ba6d21479aa3cdaf1e4084bcb2e9ad33c1402db35ef855b6e405a400d0300000000002251206ca2bd21fc40541ac9558e1c543215632eecc7c669436f1bdb10a8c2ea97f9a5400d030000000000225120d319e5ecf9b03f11ec30684fded5567b00b2585c271d62130945c02353f8bd51400d0300000000002251202e5f34c00973e3a6ccdeacc28c7994c0f345d773a382b09a331dea877deb4ab4400d03000000000022512002db565cc8f05949eedc666e5516e40233e3a8bb646ae9bb52a8378405b31c3d400d0300000000002251201ee15f85439086366d7822a16656880261cf6e76171d266ae109401f7e2db090400d030000000000225120a48aa4e2a241f11a88228a4d1c390c3076cdeacbd6e32dc850ccddbe9f4c8317400d030000000000225120b8e4dd32fc592c89d5c9cd34f9c724e02c5231b79ddaebce7e31178bc832c7a2400d030000000000225120d28865fb1e2de25889a61f81922dd3e612499262888125b28935096ecf151bdc400d030000000000225120b5b1da7738076ddc62ab5e5d432dd9b69c8b94bcbf69f2a7a2fbcb2e00c168e2400d0300000000002251200128adb161ca60cf2d792eebc01edeb507eef9a26b6291e086620f4d333f2f9c400d03000000000022512031a414653f51873c1bfdbeef40dc141eec43cfabeab7a670c18985d2463986e9400d0300000000002251207f282164ac8d6ef71cb3d15b4f4fca98d93c2a0b45290783fd06b68757101c0e400d0300000000002251208a1fb6cfe49b9a9d6189c1919fe26e29b8ebc3c856ea9d63b99df0b09f488724400d03000000000022512096289a10977378095b7b74e89c79b3911f83c3704caa18e0d356a736a499f41f400d030000000000225120934250d813563e9c4810fdf973a0f3091b900ba4c08337f4842800e046aae8f5400d030000000000225120e0cefb9755a28f5ae69bb103b45fe9dac9bee5d38d97d65293b721c3de95fcda400d0300000000002251201f9fb2d560663936c4c015f9ae69f80ae3de5a1c64eba7c35b16a3b875576458400d030000000000225120bec66229179615c91e0309b4ec9ffeb8a77f4fff5ce7c812b61c91252d3b2f30815cc07c01000000160014dbd359f23e01f8752cc193fefc04aaa9e3a4414002483045022100f5c71e82ee329df4a5ff97de36a2b2b79f86d949b7d9a3d11d32f4ab8be660b3022072f192dc45e43060bde81a4356f838e2e7110d66267e15b89afed98dab10cf4e012102836b1dbc3d40d023ec913ce3d04455a05873ea28e08c6b07536c0f08b3d3d17e00000000020000000001018c1624b7fd02ba5d018688c4d4b64b708c8a657cc7701db8ac02b970532b29ae0100000000fdffffff02af72000000000000160014e4fd3abbb644375588f09ef4899361dfe239b05fb8d1ab020000000016001498b3992769881aa136620eb1801f625b38f2c15b014072c7353f7e1ccc0916901671bded4ded93a984b1a1faf246acd794499094e9bca9a9cba56fec52dba9857573caeb4207b3b3fdfa494e0df586eb01c143667a5027d2000002000000000102caee0386f72276a521fc3364e47a162c563a5d783b07b1e6e158ec105d08fedc0300000000feffffff52c7b36f469023be085280625c16a7f541844c393d63132d9498d2407329d7b30200000000feffffff07d74d000000000000160014f6fa357adbc3efdfd88cf3dc4520a456c2e55099da4d00000000000016001449de8133adcdf7bb3681435ac08f1c61cf63bb6a45c6000000000000160014ccebf5490d07887998e364d20264ce26f4d8cc06da4d00000000000016001474b2e4c51a530f49e9fe0a153c15b2c5bb2db017da4d000000000000160014cacbbe4dfec42a4bca49102ee70cf7890437a107da4d000000000000160014f5ea3664efb45b99bbbe7a3fe71ef63269139812da4d0000000000001600143bb3a7c824ab1affaeced2997561d2e9c08c7318024730440220165bad5fe52454797aa27782bb209a650d8e275ed09bce5f399ab5f0a175e1c40220076b1a83be7ad29d3cec72cbc2486249d8a22da5f6a77c1b1b9e4225880278a301210351a58277f6cf9e1a7c48b770359a7be383a6309528674bf2a0de830ebd104d5c0247304402204bd6314bcd8926f05a6529dce35c3d9a75b7ba5a52c16dc348e998ce5f87dc5202203c404ff313b3498154f4318fa7246a94c00a197c496df4b6888c9c179b247e0a0121024547f79f1a6628d26723abfaa101accc4cfe369693b3d474771b18a245ed27b226d2000002000000000101cc3db261169c955242298e8dab61c706bc2aed52e745e4be29867cac81e77ab70400000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101408cd793eadf49fe2914d7728eddf0a8383a696d26b911487f9bb425e0e127082e6dc0a73cebd8d35230cd53b8c2a85e536d571788f990de4af0fa9767b9a26d23000000000200000000010a3b12d1df8ef6f6bf437a8cb1a5c44de442a5a24be872f4cc7685d30080f796750100000000feffffffc78bc4036394b2ada2cb10b2d39592069ce2aeb1b3b7b54fdca8b4275849140d0200000000feffffffa180251b2107744778735975322c9e777cf648d2c4eb29f57f1f6922922e3ef90100000000feffffff041cf6d6688987e00137566a0df6c5e579c2023927956806868a56c8908f77060100000000feffffffb60fdc173b95aa0c6557897a98ae189937ec1fb8c876ea1a15604d2ba8c758c80000000000feffffffd778a25494c755ea34f1fdffd4c4524d0e12718c9dab65e35ef1f7bd707f11430000000000feffffff1a6d87659c06107cc6550492761bef3d51cff46cbefd345268d7db8565f7d7cb0000000000feffffff5b91ca42c3191b1130c8796fced1895150f40abfbef937398a6e98afb556983e0300000000feffffffaf1e3bf8114dbf067133dc671eedb38445e6034faa140975efcc8e6166f9348a0100000000feffffffe12c7fb9f57d52b1c72d5d87e945f788d14f508e9b97d9fd7faafb2bff84aa4c0000000000feffffff0242fe3c0000000000160014e4fd3abbb644375588f09ef4899361dfe239b05fc973010000000000160014765028867a1b6b1195ad2d3fb6e2b065116bd1510247304402205e2bb9f8a92bd7932ef142833259840fa8c60660b6f96093e0b69bb5d47dea5e022012eb002d4bd053d96c449182a9a05cd3b3dce0f70196541e4aa69aa2a55ab6ea01210393239407efa6250ce0973f50cb829de921aee32db677817ef96ef8b56c369e8f0247304402202d4bc696752852f41213d3138f60288ec60dd0828bba0aebaa93ee2553e722c502206e43c5b3ff32f6f85f88f4e1d6c182ae4710ac81aefab6ffac984fd8e46b1e4e0121022f448382613678be144e5dcc252819333d16190cb5c3717a214e65a5a3e5672502473044022065820982ad95861e94806b981a439ee682b2cf74daaa2cc157a2bf800ac14b970220467a66443376b658eada1a3dee227ebbdc68e9e3dc824cd9874bccbe544740cd012103098239071fa5d61c8d046db4d823992efd7e9353346977314e81ea89a74a272c024730440220728a81de49e662baf3e437417a5f9979323de29e19abcf9d20bfbe72848ba23e02202b9e30ff85c517fd93f6f20c3f8f2cb8c2dafbd40aabc805e835e5bf92c143ef01210259316cde14df89e7259623b770fcc5d559bf44ab0aa94df1d22ef3eb03fa91640247304402203b74f263d7834293ec576b175a294ca8f3d2e3326f73f7e2295162c43961de930220055c52e70f32b68bf435431962ce1aa977b887fa56748f8289aec9d93d519572012103e73d95f6d4305f91910eeb22b616cb41b70ee1d2fe15f7be22f8c0f6f1e68b1d0247304402200c390f675cf6f598275745212f0dd19905f7996b0426bc1a54e679de858e59c102207f65baede91dbc069def5cc4dee53e86239e4a0d7de0fa1deb9834bbe80ec00c01210352c76e118039f87d7414b6f43ebea6b2751ec7be97bee5482207af8bbd2588eb0247304402200c1ccaeaf7a27910e35ab2cbd4097aa69a00287149740b635f5910269a252d3e02202daef72974401ae19473e95da17c823ed28d879205edc61ee7be729025fec4be012102d80c616c1fb9dba1b4ae73313d88f03a68ade3a4760ea12ca14a13a7ade2b97702473044022067bae6844b4139f88f7d8ee1182e6366048ccf495c0c59169a7fa3e0a9c7bb560220196ab2d2c740274b4eb68b0d1c7726d7e956206d0b2d41cfeb4ed8aa6dc8ec9e0121020b0318da2b655e849a5a4739a7b11146b1cc5e901f4e25e7febea0f26f83a65102473044022051e01b410b032dcc45d26817ea95acfbb9ff0bacc4cb21a8275af38181824c3b0220719cf12dab0a0a16483a5bb4047055fb1aecd3a822e5ef7e672d518037950f74012102a9f47ae23f06e0232e87183f7d0e779693271034a10042fc8a6d3217dfc9f7750247304402202c139393fc08c979764d9ecfd5634ca782736b389c8aa01042f61e3cf388f9ca022005b76058fd540e3ab659db3404b862c26182168c9299c63c592b8c2960d76e8401210397653767e64932ea2c83c0238926a74c711132cfbd3c4f03a35372fa7426d89ce6d1000002000000000102b381d86b5991500119f1bd95e3fcbcc4a9107c7ea21bda41ff298358f2d1fd180700000000ffffffff01f01c8efa965c8c2cf4f4b18cd297675d09cba71e1473b419963b4faf1d28b90100000000ffffffff0260e316000000000022512080eb3e9db450c51afa4daf8f1b57c770c556991d91f36887d436a3dde47c0a869215000000000000225120786d148fb2d85e10db8969dba73a7351786b4b7ddb9efcc67436f740598e548d0140be9962adedaf1a51f62a18f12e5b53c476bf9b946ced6b4f8445fb7fd32364a49e85a2fb2982a5f307a82f244234c16fb19a467f9a0da173359bae4d4b23ddde014050298fbcec95a0a96848efe3b4ec24b42ad1b08deb2d0c26057b1b0ef1da667c098122416c8b389e391cb365d1fdab4b1c33a975a2cc45ca8cb20315c9f0ac1f00000000020000000001010722303828d572d3fb1e3f646a052ce68451473a86cce02b726baaf7dae3ca570200000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101400dd9e3b6563c580940898e86aba16bc3925bf42bc4183c310d5334c7753fd21f69d65ccad54b8c902dbb0920c32119296a10f1d41e8629bedc6207f85551e5f6000000000200000000010122aee43b30cdd01765a316c5d6837a540af4a9c6690cb0e440ddfc5608eb064f0000000000fdffffff0225c2d1cc1e0000001600147b458433d0c04323426ef88365bd4cfef141ac758813000000000000225120d0f61eac8291b8689461aa5e08e2aaaa627199196c37b9bd2a9959182bcf6d0102473044022015ff9f5c1cb9b0874b54dce2aef396522d2ef20891cd0724a7409c43ce34de5b02203d2b9d5ab8bbec6e7cd5d5e3eb206375fb8b386e911c026114875760099a05ad0121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb3000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860000000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140091ab528a2910bc686b4dac9912da4a59df173e8be7befed11f85c487bb7b68815c3a4c4a457159ed5e1f7999045f8b6dcd5ae63643aefbd1eeb6a749e3ecb260000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0100000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140eef79c5d2ddab489e1fcfa3a82b554dfafa637017225592c97ece6df7e792bd4b8c74c3afc098203cc8578bcaf9bac77d29d3db13be7a8fd8c9d31d7685a80c4000000000200000001d0e9cfbcdcfbd1422632c90586365e85fb4d6a9f3a186c6459bc115ccc5db820010000006a47304402205227e61a70642da96194d94cde92927b242386e98d876667e7a87725b485d2da02200bc948407069f2ddc17cfefbe06ddfd290a6b5cc51a842b23917973d938ad71f012103816c333f0b3de4ccc0c19b0839d6fb9b05f17d6c84af91a48f93f328957d600bfdffffff024ef72506000000002251205ca3400e7f0a03ccb0d1d8591446edf094d2e2b34ad347cbcc7a0333819031cc92560000000000002251206c9d33e2c4a8bd1054afe49bd88f0867b60b254ffb0e58239b5b31059b4255e327d2000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0600000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101403728e23db6509b7bf57763959ba151341d4012e206f159af878242360eab3a598a5c1272bb603dd580c0e7771602d0d0d334e227cf24e658e092e49947a86f440000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0c00000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101405383d27fa066921b4bfaf882088b68cc2001bceeb7455681f17db44fa4c1fb7cb58da79c1335fa116d7acd625bcfcc207fae7405bb3d967036b73cce0a3f87c60000000002000000000101805fd5f2b35a00fd4bd80b6a4e7eea9aef743b416d84d2e2659170fccba0c22a0100000000ffffffff02204e00000000000022512080eb3e9db450c51afa4daf8f1b57c770c556991d91f36887d436a3dde47c0a8682ad6c00000000002251208a482830e94b85d843e95c2448f6d160b056aea668dcdd9b8d7f218094411f180140e61574ffc8cc85dd0de1b0d8cc1b113ef6211b7e165d368a0fafaa578e8056dd35738bbcf047f01923bcc6a130385c600473a78ce3dc91df8460c9d2e340bf060000000002000000000101910f822c831c0a256bc01e50c590f91c554f46b008f0180c5e3131fedaca51630100000000ffffffff02803801000000000022512080eb3e9db450c51afa4daf8f1b57c770c556991d91f36887d436a3dde47c0a8668746b00000000002251208a482830e94b85d843e95c2448f6d160b056aea668dcdd9b8d7f218094411f18014032f909383a2ca58020a9180fdfe210158c7b7397cd168d928533e3be619098e77d8ce6be4688bc9bb14d937ee77c1d54944f0f3a20a1c2e2d9b9b85f4ea557ea0000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0200000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140cd136f7ec1f4beb9f063556f66a446037c8b8cf37f746c1b8748f688ede7eca5367f8cbaa6353681ea515f469275103dbc7e8175056a99094fe56a43b0c4ddbe000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860900000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140ad023b4f959806fff187247cdbc57fc7159bbdc45afe5492fe78314f3396f0ba1aaf686b8e3c53bb6182bd64cbab0380dfec36677c98891cc3fcdbea6227d3a40000000002000000000101570f9ab70e0ed40f234e0672443e45bab32577dffefb6db22f7c131699223eae0000000000feffffff02894d00000000000016001410488094091f5aa7d04a994ff937a1ffdb974bf718e8000000000000160014fecc9392d0da66d2f61ab86d90be2d339d38fc7302473044022076fb7191ce8102b636ae02d581b44618ade858e86f70e495c7826d4e8131de1802204ab87877d842de643417732ba272612c6a4699d1a00fa01f0382c5a7a6b4df02012102d8058c60963858e23ee0cc55c3cb5eca6216c0989060da353774c9bc7289297727d200000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860700000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140e289a5ece4b6d1bda4f28c46ce9707f6052924aa801649f469f8d28b906709c1b32dc09e0d86b8326d202dbacadfe5ed9f70c9a6bbd409a5b7072c8e132fb9e8000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860300000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101405c5adcb347f17b947abeebf4146ecf2723ed2257fba39e3ddf02e56ca4907afb5e6871e650eb287d2173abb9d4667f2b14904abde85e8f0e2f82759cee5decdd0000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0400000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140b1e168a3d2ff0723f9c32aeb3c1c2522829a58418db38cfd94422538fb172e81d4a8baeb2f0f4fe32cbd4f4b7983d982e4f9283098acb169e69f7d86f9cf60b800000000020000000001014049c949ab389bd8385b1b4dae60d3027646bca0f6bc0b56f341f43420f698210100000000ffffffff02905f01000000000022512080eb3e9db450c51afa4daf8f1b57c770c556991d91f36887d436a3dde47c0a863e146a00000000002251208a482830e94b85d843e95c2448f6d160b056aea668dcdd9b8d7f218094411f180140ee24fe241950f9ad1356d6817872d97e4a6bc2ebf99a14f83d7805440ec4532a80425d019cc1d65c2397c048709e64c0f53ac376db8a9285558b1f96565a6dea0000000002000000000101cc3db261169c955242298e8dab61c706bc2aed52e745e4be29867cac81e77ab70200000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140fc85ae0bc99d4f03162182e73f1114815c32808dbfb8f1f9604e8d13c3f08a88bc19e17999cbb26dcdace1ad2994da9747c1efac609178bcbab61c0d4f8c532c000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860400000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc11014010db562114bba933a0f869b7ca2ca1d1febfb2698e145686f11037fb8205f902ce4b1cd22ecd0815356f8203da5d08b1f07a81eb167196f004453f738af687d4000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860100000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101403158fc9a8ba466d3785ec8ff1f9950cad9b8a2da2a5fcdf54177219ecc5895c98b2ab394402924c4fe630c2c5de7fc3a5db1350a82654984ea586c8c53e463dc000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860500000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140caf8e0fbf94b44a00334e61b500f1837b3e7808548916cd8e8db14d153ac110d8770716e50d618f223e0d711111a47803b13312e825b47d281c0bfef369fd2980000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb1100000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc1101404016086cd5b0895739606edeaefdf817b93eb09071e95ea23f8c47986997c8de0fbc5a1ce406793bac8458625fff2e51591e02ced594b2345b1c3277a3251bf20000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0a00000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140ab917683a9a9f39cedc8395f11b7bc2445c2402eecc2e8ad67c4fd804328d17b2e4b44e083f3874385a2a5c44aeaa382cc6f5178a72538c491e22bf82487462200000000020000000001010722303828d572d3fb1e3f646a052ce68451473a86cce02b726baaf7dae3ca570600000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140f10df53597f6ee50a44ccf6e643ccb723f224dc96c00e14c86aef5116b4c82142953b4db3503ee1d6cfed2ae0cb7acd94523516ef110b3042249602765c9bc6f0000000002000000000103c4b8ab4e4a2162195dca57d23a2f0be7115a16f7ee96eea843af779843fda6170500000000fffffffff353ae7c11bc07651d38a7d72cb50ae9375648a3497e505b16b4cd9f48613cca0100000000ffffffff2ec1cee2a9c91e040bc3632e6877a983d85e4c117b496077932ab09a8566d7880100000000ffffffff02c0c62d000000000022512080eb3e9db450c51afa4daf8f1b57c770c556991d91f36887d436a3dde47c0a86b73e0f000000000022512020cb02edeb4b69afcd08a6901514629b5531e2c6a30ce112eebe5a49eb94bf9c0140e444abb9bc1cbc406071d6318c3fb059e5ed6b538391f47ba5e5889a06f43156254d4ee107f2549b2a0627d19591c857d4376d8ff5801d0267ae31337ba8d8d60140031ed566b1f79ef05134474910635803fd050277a96c8f40f29614d7cf5fcfb5024ea7f799c3944ba9c4e29d36c6a4156818257c2bf7263382a0742b67139859014078e54fd05719f77b3123691b03bca895ab8d3d0038b0d1354a83dc16ad818f0d79ad2f7492a01fa8ed5d9d81360947c401cac4d75911068de3a19e49db1b9ad6000000000200000000010108eac5eab9998b46ccdb0fca2aee70062cf48d2351ee9bff906296fb520e1c860600000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140be76626a3f207e60628c09d2158510f27f030fe2a7c12617403ee1fe07efcff7bd77de49e47b04b709a4a721454524320b4f0b24f7ef675a3e34e43c017078ea0000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0500000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140de11962fa987dae8d84326bb9ea7c3593d59f6e736b1eafc752483172f9437a6b75fbc54c01dd2e2e49eb7016ec7ea9e51d0bedd54c4bb416fc198422cb525db0000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb0f00000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc11014087013a16f5728d3d51ac12699d3000614dc0a8db5bf7b08485e0ab6b0d0d070cb4e27e8ddb5466f763eb66eec504281e749f3c5340af4121eb10ac2c3cfa915e00000000020000000001010e77b7bccc47c756b0e6327627940a650d411608e0cd0784176610d7b4c768250000000000ffffffff018a821e00000000002251209321b660eaf1d8487ecc799c9f3bbb74b7bb1793de9df41d04a479669b2617300140705be8f3732c372a836804334dfc6f16d511b18ad448123cd877c548e1b0d6ce0b43764376c19d401ca9cb98079c6432be682594ba29096a9698238cfc822294000000000200000000010180ce346d13519be8de8c9221e776b877694628c88dcb570850e628032e81b3520000000000fdffffff0217e7d7e6160000001600147b458433d0c04323426ef88365bd4cfef141ac758813000000000000225120d0f61eac8291b8689461aa5e08e2aaaa627199196c37b9bd2a9959182bcf6d010247304402202cd798c91fb2974277c969a920bf20797395ed0d1824321f57b9d5f83a59121602202a392615fede776c6348d608775fc6077914efc2b9b982c5bcdccf76cc1b35f40121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb30000000002000000000101d8773a94e31a4b5adcea618a6c8532f4141ac88a354fffd501958d6a6b7e98020000000000fdffffff020d5f73416f000000225120aac35fe91f20d48816b3c83011d117efa35acd2414d36c1e02b0f29fc3106d900ff200000000000016001400f56bc22372ce3648abc4af21baea9a72b3475e01400051d2c9b67cc536921a56bce9a6b50498f4e72137bdae6027e4e8d9adb7d9d9cf181129ed5fd2f4eac0bbc4cefcff468fba485c667b2ee93242fa185010721200000000020000000001010722303828d572d3fb1e3f646a052ce68451473a86cce02b726baaf7dae3ca570800000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140f94e3f51bb785ffdb773759b48048a00cec748c7cd880483c29ead5be682c632f08a24ae9961bfa3f084996ffd957c15a8e26b1cea6476822bdf6064c67040de0000000002000000000101771928fe801bc5b368b7899491efba72c5a761bb09be761ce7f80f14851bf8cb1000000000ffffffff01d10c0300000000002251206a0cc6c8cc7caae4bbb6aadf779ccbd5689cd18c3ed90a5229870fcf9e4bdc110140c9fe47399fc6cc2ed357a46967a006e8ac39241c200d4757cbf43501c5e9c015ff17c01c6a4ec8b99ea34ab2d813c8bcad02654543bc7d69bd2624b8aea84ec700000000020000000001012d71f720be469ccdd6dc41b6a7d09c82e895f6ed78fa7df7af350ac9e78933ee0000000000fdffffff02ea0f83c5000000001600147b458433d0c04323426ef88365bd4cfef141ac758813000000000000225120d0f61eac8291b8689461aa5e08e2aaaa627199196c37b9bd2a9959182bcf6d010247304402202e354e8f135603dd752b999dbeeced525d35b14a40e356ad7c91149dc99d496f022076bdb2bec3317f3889bb9fba5bc6e9b52064f99c4c223186fbfd32e7f54eb33f0121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000").unwrap()).unwrap();
        let tx_vec: Vec<CircuitTransaction> = block
            .txdata
            .iter()
            .map(|tx| CircuitTransaction(tx.clone()))
            .collect();
        let txid_vec: Vec<[u8; 32]> = tx_vec.iter().map(|tx| tx.txid()).collect();
        let merkle_tree = BitcoinMerkleTree::new(txid_vec);
        let merkle_root = merkle_tree.root();
        assert_eq!(
            merkle_root,
            block.header.merkle_root.as_raw_hash().to_byte_array()
        );
        let mid_state_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new_mid_state(&tx_vec);
        let mid_state_merkle_root = calculate_sha256(&mid_state_merkle_tree.root());
        assert_eq!(
            mid_state_merkle_root,
            block.header.merkle_root.as_raw_hash().to_byte_array()
        );
        for (i, tx) in tx_vec.into_iter().enumerate() {
            let mid_state_txid = tx.mid_state_txid();
            let merkle_proof_i = mid_state_merkle_tree.generate_proof(i as u32);
            assert!(verify_merkle_proof(
                mid_state_txid,
                &merkle_proof_i,
                merkle_root
            ));
        }
    }

    // Should panic
    #[test]
    #[should_panic(expected = "Duplicate hashes in the Merkle tree, indicating mutation")]
    fn test_malicious_merkle_tree_1() {
        let txid_vec = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let _merkle_tree = BitcoinMerkleTree::new(txid_vec);
        let malicious_tx_vec = vec![[1u8; 32], [2u8; 32], [3u8; 32], [3u8; 32]];
        let _malicious_merkle_tree = BitcoinMerkleTree::new(malicious_tx_vec);
    }

    // Should panic
    #[test]
    #[should_panic(expected = "Duplicate hashes in the Merkle tree, indicating mutation")]
    fn test_malicious_merkle_tree_2() {
        let txid_vec = vec![
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        ];
        let _merkle_tree = BitcoinMerkleTree::new(txid_vec);
        let malicious_tx_vec = vec![
            [1u8; 32], [2u8; 32], [3u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [5u8; 32],
            [6u8; 32],
        ];
        let _malicious_merkle_tree = BitcoinMerkleTree::new(malicious_tx_vec);
    }

    #[test]
    /// a b c
    /// but try to cheat and say c is index 3
    #[should_panic(expected = "Merkle proof is invalid: left hash matches combined hash")]
    fn test_merkle_root_with_proof_wrong_idx_a() {
        let mut transactions: Vec<CircuitTransaction> = vec![];
        for i in 0u8..3u8 {
            let tx = Transaction {
                version: Version::non_standard(i as i32),
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            transactions.push(CircuitTransaction(tx));
        }
        let mut tx_hashes: Vec<[u8; 32]> = vec![];
        for tx in transactions.iter() {
            tx_hashes.push(tx.txid());
        }
        let tree = BitcoinMerkleTree::new(tx_hashes.clone());
        let mid_state_tree = BitcoinMerkleTree::new_mid_state(&transactions);
        let tree_root = tree.root();
        let mid_state_root = mid_state_tree.root();
        assert_eq!(tree_root, calculate_sha256(&mid_state_root));
        let proof = mid_state_tree.generate_proof(2);
        assert!(verify_merkle_proof(
            transactions[2].mid_state_txid(),
            &proof,
            tree_root
        ));

        // Now try to cheat and say c is at index 3
        let idx_path = mid_state_tree.get_idx_path(2); // Get from real index 2
        let false_proof = BlockInclusionProof::new(3, idx_path);
        verify_merkle_proof(transactions[2].mid_state_txid(), &false_proof, tree_root);
    }

    #[test]
    /// a b c d e f
    /// but try to cheat and say e is index 6
    #[should_panic(expected = "Merkle proof is invalid: left hash matches combined hash")]
    fn test_merkle_root_with_proof_wrong_idx_b() {
        let mut transactions: Vec<CircuitTransaction> = vec![];
        for i in 0u8..6u8 {
            let tx = Transaction {
                version: Version::non_standard(i as i32),
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            transactions.push(CircuitTransaction(tx));
        }
        let mut tx_hashes: Vec<[u8; 32]> = vec![];
        for tx in transactions.iter() {
            tx_hashes.push(tx.txid());
        }
        let tree = BitcoinMerkleTree::new(tx_hashes.clone());
        let mid_state_tree = BitcoinMerkleTree::new_mid_state(&transactions);
        let tree_root = tree.root();
        let mid_state_root = mid_state_tree.root();
        assert_eq!(tree_root, calculate_sha256(&mid_state_root));
        let proof = mid_state_tree.generate_proof(4);
        assert!(verify_merkle_proof(
            transactions[4].mid_state_txid(),
            &proof,
            tree_root
        ));

        // Now try to cheat and say e is at index 6
        let idx_path = mid_state_tree.get_idx_path(4); // Get from real index 4
        let false_proof = BlockInclusionProof::new(6, idx_path);
        verify_merkle_proof(transactions[4].mid_state_txid(), &false_proof, tree_root);
    }
}
