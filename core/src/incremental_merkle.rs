use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

pub type Data = [u8; 32];
const EMPTYDATA: Data = [0; 32];

const DEPTH: usize = 3;
const MAX_DEPTH: usize = 32;

lazy_static! {
    static ref ZEROES: [Data; MAX_DEPTH + 1] = {
        let mut a = [EMPTYDATA; MAX_DEPTH + 1];
        for i in 0..DEPTH {
            a[i + 1] = IncrementalMerkleTree::HASH_FUNCTION(a[i], a[i]);
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct IncrementalMerkleTree {
    pub filled_subtrees: [Data; DEPTH],
    pub root: Data,
    pub index: u32,
}

impl IncrementalMerkleTree {
    const HASH_FUNCTION: fn(Data, Data) -> Data = sha256;

    pub fn initial() -> Self {
        Self {
            filled_subtrees: [EMPTYDATA; DEPTH],
            root: ZEROES[DEPTH],
            index: 0,
        }
    }

    pub fn add(&mut self, a: Data) {
        let mut current_index = self.index;
        let mut current_level_hash = a;

        for i in 0..DEPTH {
            let (left, right) = if current_index % 2 == 0 {
                self.filled_subtrees[i] = current_level_hash;
                (current_level_hash, ZEROES[i])
            }
            else {
                (self.filled_subtrees[i], current_level_hash)
            };
            current_level_hash = IncrementalMerkleTree::HASH_FUNCTION(left, right);
            current_index /= 2;
        }
        self.root = current_level_hash;
        self.index += 1;
    }
}
