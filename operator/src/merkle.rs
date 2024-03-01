use crate::config::ZEROES;
use crate::constant::{Data, EMPTYDATA};
use circuit_helpers::incremental_merkle::IncrementalMerkleTree;
use circuit_helpers::sha256_hash;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MerkleTree<const DEPTH: usize> {
    data: Vec<Vec<Data>>,
    pub index: u32,
}

impl<const DEPTH: usize> Default for MerkleTree<DEPTH>
where
    [Data; DEPTH]: Serialize + DeserializeOwned + Copy,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> MerkleTree<DEPTH>
where
    [Data; DEPTH]: Serialize + DeserializeOwned + Copy,
{
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

    pub fn add(&mut self, a: Data) {
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

    pub fn path(&self, index: u32) -> [Data; DEPTH] {
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

    pub fn root(&self) -> Data {
        self.data[DEPTH][0]
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
