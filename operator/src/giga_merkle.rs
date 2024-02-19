// Giga Merkle Tree is used to store all of the preimages which lead to the claim of the deposits.
// For each period, the connector UTXO tree will represent a node in the Giga Merkle Tree.
// The Giga Merkle Tree will be used to prove the inclusion of the preimages in the connector UTXO tree,
// depending on the number of periods that have passed.

use circuit_helpers::constant::HASH_FUNCTION_64;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct GigaMerkleTree {
    pub num_rounds: usize,
    pub internal_depth: usize,
    pub internal_roots: Vec<[u8; 32]>,
    pub data: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl GigaMerkleTree {
    pub fn new(num_rounds: usize, internal_depth: usize, leaves_info: Vec<Vec<[u8; 32]>>) -> Self {
        assert_eq!(leaves_info.len() as u32, u32::pow(2, internal_depth as u32) * (num_rounds as u32));
        let mut internal_roots: Vec<[u8; 32]> = Vec::new();
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        let mut data: Vec<Vec<[u8; 32]>> = Vec::new();

        for i in 0..num_rounds {
            for j in 0..u32::pow(2, internal_depth as u32) as usize {
                let mut hasher = Sha256::new();
                for elem in &leaves_info[i * (u32::pow(2, internal_depth as u32) as usize) + j] {
                    hasher.update(elem);
                }
                let hash = hasher.finalize().try_into().unwrap();
                leaves.push(hash);
            }
        }
        data.push(leaves);

        let mut level = 0;

        while level < internal_depth + (num_rounds.ilog(2) as usize) {
            let mut level_data: Vec<[u8; 32]> = Vec::new();
            for i in 0..(u32::pow(2, internal_depth as u32 + ((num_rounds as u32).ilog(2)) - level as u32) / 2) as usize {
                let mut hasher = Sha256::new();
                hasher.update(data[level][i * 2]);
                hasher.update(data[level][i * 2 + 1]);
                let hash = hasher.finalize().try_into().unwrap();
                level_data.push(hash);
            }
            assert_eq!(level_data.len() as u32, u32::pow(2, (internal_depth as u32) + ((num_rounds as u32).ilog(2)) - (level as u32) - 1));

            data.push(level_data.clone());
            level = level + 1;

            if level == internal_depth {
                internal_roots = level_data.clone();
            }
        }
        
        let root = data[data.len() - 1][0];

        Self {
            num_rounds,
            internal_depth,
            internal_roots,
            data,
            root,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn get_merkle_proof(&self, period: usize, internal_index: usize) -> Vec<[u8; 32]> {
        let mut index = period * u32::pow(2, self.internal_depth as u32) as usize + internal_index;
        let mut proof: Vec<[u8; 32]> = Vec::new();
        let mut level = 0;
        while level < self.internal_depth + self.num_rounds.ilog(2) as usize {
            if index % 2 == 1 {
                proof.push(self.data[level][index - 1]);
            } else {
                proof.push(self.data[level][index + 1]);
            }
            level += 1;
            index = index / 2;
        }
        proof
    }

    pub fn verify_merkle_proof(&self, period: usize, internal_index: usize, proof: Vec<[u8; 32]>) -> bool {
        let mut index = period * u32::pow(2, self.internal_depth as u32) as usize + internal_index;
        let mut hash = self.data[0][index];
        for elem in proof {
            if index % 2 == 0 {
                hash = HASH_FUNCTION_64(hash, elem);
            } else {
                hash = HASH_FUNCTION_64(elem, hash);
            }
            index = index / 2;
        }
        return hash == self.root;
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::{rngs::OsRng, Rng};

    #[test]
    fn test_new_giga_merkle_tree() {
        let num_rounds = 4;
        let internal_depth = 2;
        let mut rng = OsRng;
        let mut leaves_info = Vec::new();
        for _ in 0..16 {
            let mut leave_info = Vec::new();
            leave_info.push(rng.gen::<[u8; 32]>());
            leaves_info.push(leave_info);
        }
        let giga_merkle_tree = GigaMerkleTree::new(num_rounds, internal_depth, leaves_info);
        println!("{:?}", giga_merkle_tree);
    }

    #[test]
    fn test_giga_merkle_proof() {
        let num_rounds = 4;
        let internal_depth = 2;
        let mut rng = OsRng;
        let mut leaves_info = Vec::new();
        for _ in 0..16 {
            let mut leave_info = Vec::new();
            leave_info.push(rng.gen::<[u8; 32]>());
            leaves_info.push(leave_info);
        }
        let giga_merkle_tree = GigaMerkleTree::new(num_rounds, internal_depth, leaves_info);
        for i in 0..16 {
            let (p, q) = (i / 4, i % 4);
            let proof = giga_merkle_tree.get_merkle_proof(p, q);
            assert_eq!(giga_merkle_tree.verify_merkle_proof(p, q, proof), true);
        }
    }

}

