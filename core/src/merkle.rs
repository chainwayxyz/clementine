use clementine_circuits::constants::{EMPTYDATA, ZEROES};
use clementine_circuits::incremental_merkle::IncrementalMerkleTree;
use clementine_circuits::{sha256_hash, HashType};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkleTree<const DEPTH: usize> {
    data: Vec<Vec<HashType>>,
    pub index: u32,
}

impl<const DEPTH: usize> Default for MerkleTree<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> MerkleTree<DEPTH> {
    pub fn new() -> Self {
        Self {
            data: {
                let mut v = Vec::new();
                for _ in 0..DEPTH + 1 {
                    v.push(Vec::new());
                }
                v
            },
            index: 0,
        }
    }

    pub fn add(&mut self, a: HashType) {
        let mut current_index = self.index;
        let mut current_level_hash = a;
        let trz = self.index.trailing_zeros();

        for i in 0..DEPTH + 1 {
            let (left, right) = if current_index % 2 == 0 {
                (current_level_hash, ZEROES[i])
            } else {
                (self.data[i][current_index as usize - 1], current_level_hash)
            };
            if i > trz as usize {
                self.data[i][current_index as usize] = current_level_hash;
            } else {
                self.data[i].push(current_level_hash);
            }
            current_level_hash = sha256_hash!(left, right);
            current_index /= 2;
        }
        self.index += 1;
    }

    pub fn path(&self, index: u32) -> [HashType; DEPTH] {
        let mut p = [EMPTYDATA; DEPTH];
        let mut i = index as usize;
        for level in 0..DEPTH {
            let s = if i % 2 == 0 { i + 1 } else { i - 1 };
            p[level] = if s < self.data[level].len() {
                self.data[level][s]
            } else {
                ZEROES[level]
            };
            i /= 2;
        }
        p
    }

    pub fn root(&self) -> HashType {
        if self.data[DEPTH].is_empty() {
            ZEROES[DEPTH]
        } else {
            self.data[DEPTH][0]
        }
    }

    /// TODO: Make this more efficient
    pub fn index_of(&self, a: HashType) -> Option<u32> {
        for i in 0..self.index {
            if self.data[0][i as usize] == a {
                return Some(i);
            }
        }
        None
    }

    pub fn to_incremental_tree(&self, index: u32) -> IncrementalMerkleTree<DEPTH> {
        let mut fst = [EMPTYDATA; DEPTH];
        let mut i = index as usize;
        let mut current_level_hash = self.data[0][i];
        for level in 0..DEPTH {
            if i % 2 == 0 {
                fst[level] = current_level_hash;
            } else {
                fst[level] = self.data[level][i - 1];
            }
            let (left, right) = if i % 2 == 0 {
                (current_level_hash, ZEROES[level])
            } else {
                (self.data[level][i - 1], current_level_hash)
            };
            current_level_hash = sha256_hash!(left, right);
            i /= 2;
        }
        IncrementalMerkleTree {
            filled_subtrees: fst,
            root: current_level_hash,
            index,
        }
    }
}

// cargo test --package operator --lib  -- merkle::tests::test_merkle_cross_check --nocapture
#[cfg(test)]
mod tests {
    use crate::merkle::MerkleTree;
    use clementine_circuits::incremental_merkle::IncrementalMerkleTree;

    #[test]
    fn test_merkle_cross_check() {
        let mut mt = MerkleTree::<31>::new();
        let mut imt = IncrementalMerkleTree::<31>::new();
        let contract_empty_root: [u8; 32] = [
            0x2a, 0xfd, 0x59, 0x5f, 0x48, 0x6a, 0x77, 0x1b, 0xf9, 0x65, 0x3b, 0x93, 0x33, 0xd7,
            0x8b, 0xf1, 0x01, 0xfa, 0xd1, 0xf5, 0xdd, 0xb0, 0xdb, 0x96, 0x0c, 0x5a, 0x14, 0x50,
            0x20, 0x00, 0x61, 0xdb,
        ];
        assert_eq!(mt.root(), contract_empty_root);
        assert_eq!(mt.root(), imt.root);
        let a = [1 as u8; 32];
        mt.add(a);
        imt.add(a);
        let contract_insert_1_root: [u8; 32] = [
            0x15, 0xf4, 0x6f, 0x6e, 0x63, 0xb6, 0xbf, 0x80, 0xf7, 0x1e, 0x67, 0xa6, 0x70, 0x46,
            0xe5, 0xda, 0xce, 0x83, 0x4e, 0x54, 0x2c, 0xa9, 0x0d, 0x2e, 0xd2, 0x35, 0x91, 0x10,
            0x55, 0xa1, 0x0b, 0x33,
        ];
        assert_eq!(mt.root(), contract_insert_1_root);
        assert_eq!(mt.root(), imt.root);
    }
}
