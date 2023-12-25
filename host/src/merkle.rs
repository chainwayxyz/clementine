use bridge_core::incremental_merkle::{Data, EMPTYDATA};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

pub const DEPTH: usize = 32;
const MAX_DEPTH: usize = 32;

lazy_static! {
    static ref ZEROES: [Data; MAX_DEPTH + 1] = {
        let mut a = [EMPTYDATA; MAX_DEPTH + 1];
        for i in 0..DEPTH {
            a[i + 1] = MerkleTree::HASH_FUNCTION(a[i], a[i]);
        }
        a
    };
}

pub fn sha256(a: Data, b: Data) -> Data {
    let mut c = [0_u8; 2 * 32];
    c[..32].copy_from_slice(&a);
    c[32..].copy_from_slice(&b);
    let mut hasher = Sha256::new();
    hasher.update(c);
    hasher.finalize().try_into().unwrap()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MerkleTree {
    data: Vec<Vec<Data>>,
    index: u32,
}

impl MerkleTree {
    const HASH_FUNCTION: fn(Data, Data) -> Data = sha256;

    pub fn initial() -> Self {
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
            }
            else {
                (self.data[i][current_index as usize - 1], current_level_hash)
            };
            if i <= trz as usize {
                self.data[i][current_index as usize] = current_level_hash;
            }
            else {
                self.data[i].push(current_level_hash);
            }
            current_level_hash = MerkleTree::HASH_FUNCTION(left, right);
            current_index /= 2;
        }
        self.index += 1;
    }

    pub fn path(&self, index: u32) -> [Data; DEPTH] {
        let mut p = [EMPTYDATA; DEPTH];
        let mut i = index as usize;
        for level in 0..DEPTH {
            if i % 2 == 0 {
                p[i] = self.data[level][i + 1];
            }
            else {
                p[i] = self.data[level][i - 1];
            }
            i /= 2;
        }
        p
    }

    pub fn root(&self) -> Data {
        self.data[DEPTH + 1][0]
    }
}

pub fn merkle_test() {

}

